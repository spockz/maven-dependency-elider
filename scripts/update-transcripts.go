// WHY: Captures configured Maven goal output into reviewable documentation blocks with conservative normalization and drift checking.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// maxTranscriptWorkers bounds Maven concurrency to the four configured fixture projects.
const maxTranscriptWorkers = 4

type manifest struct {
	Why           string       `json:"$comment"`
	SchemaVersion int          `json:"schemaVersion"`
	Setup         setupCommand `json:"setup"`
	Invocations   []invocation `json:"invocations"`
}

type setupCommand struct {
	WorkingDirectory   string            `json:"workingDirectory"`
	Command            string            `json:"command"`
	Args               []string          `json:"args"`
	Environment        map[string]string `json:"environment"`
	ExpectedExitCode   int               `json:"expectedExitCode"`
	EvidencePathMarker string            `json:"evidencePathMarker"`
}

type invocation struct {
	ID               string   `json:"id"`
	TargetDocument   string   `json:"targetDocument"`
	WorkingDirectory string   `json:"workingDirectory"`
	Command          string   `json:"command"`
	Args             []string `json:"args"`
	Goal             string   `json:"goal"`
	RenderMode       string   `json:"renderMode"`
	ExpectedExitCode int      `json:"expectedExitCode"`
	MaxGraphRows     int      `json:"maxGraphRows,omitempty"`
	RequiredOutput   []string `json:"requiredOutput,omitempty"`
}

type commandResult struct {
	Output   string
	ExitCode int
}

var (
	snapshotAt   = regexp.MustCompile(`(?m)^(\[INFO\] Snapshot: last successful elide run at )[^\s]+`)
	buildTime    = regexp.MustCompile(`(?m)^(\[INFO\] Total time:)\s*.*$`)
	finishedAt   = regexp.MustCompile(`(?m)^(\[INFO\] Finished at:)\s*.*$`)
	cacheHitTime = regexp.MustCompile(`maximum validated hit [0-9.]+ ms`)
	processID    = regexp.MustCompile(`(?i)\b(pid|process id)(\s*[:=]\s*)[0-9]+`)
	markerID     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	safeArg      = regexp.MustCompile(`^[A-Za-z0-9_./:=,@%+${}-]+$`)
)

func main() {
	update := flag.Bool("update", false, "rewrite generated transcript blocks")
	check := flag.Bool("check", false, "compare generated transcript blocks without writing")
	flag.Parse()
	if *update == *check {
		fail("choose exactly one of --update or --check")
	}
	if err := execute(*update); err != nil {
		fail(err.Error())
	}
}

func execute(update bool) (resultErr error) {
	root, err := filepath.Abs(".")
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	file, err := os.Open(filepath.Join(root, "scripts", "transcripts-manifest.json"))
	if err != nil {
		return fmt.Errorf("open transcript manifest: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var config manifest
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("decode transcript manifest: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return err
	}
	if err := validateManifest(config); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, ".scratch", "transcript-analysis"), 0o700); err != nil {
		return fmt.Errorf("create transcript analysis output directory: %w", err)
	}

	evidencePath, err := prepareEvidence(root, config.Setup)
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			fmt.Fprintf(os.Stderr, "Transcript fixture evidence retained at %s\n", evidencePath)
			return
		}
		if err := os.RemoveAll(evidencePath); err != nil {
			resultErr = fmt.Errorf("remove transcript fixture evidence at %s: %w", evidencePath, err)
		}
	}()
	return generateAndReconcile(root, evidencePath, config.Invocations, update, func(item invocation) (commandResult, error) {
		return runInvocation(root, evidencePath, item)
	})
}

func generateAndReconcile(root, evidencePath string, items []invocation, update bool, run func(invocation) (commandResult, error)) error {
	results, err := runInvocations(root, evidencePath, items, maxTranscriptWorkers, run)
	if err != nil {
		return err
	}
	outputs := make(map[string]string, len(items))
	for i, item := range items {
		result := results[i]
		transcript := renderCommand(item)
		transcript += fmt.Sprintf("\nProcess exit status: %d\n", result.ExitCode) + result.Output
		lines := normalizeOutput(transcript, root, evidencePath)
		if item.MaxGraphRows > 0 {
			lines = elideGraphRows(lines, item.MaxGraphRows)
		}
		outputs[item.ID] = strings.Join(lines, "\n")
	}

	documents := make(map[string]string)
	for _, item := range items {
		if _, exists := documents[item.TargetDocument]; exists {
			continue
		}
		path, err := safeRepositoryPath(root, item.TargetDocument)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read transcript document %s: %w", item.TargetDocument, err)
		}
		documents[item.TargetDocument] = string(content)
	}

	generated := make(map[string]string, len(documents))
	for document, content := range documents {
		documentInvocations := make([]invocation, 0)
		for _, item := range items {
			if item.TargetDocument == document {
				documentInvocations = append(documentInvocations, item)
			}
		}
		updated, err := replaceBlocks(content, documentInvocations, outputs)
		if err != nil {
			return fmt.Errorf("validate transcript markers in %s: %w", document, err)
		}
		generated[document] = updated
	}

	return reconcileDocuments(root, update, documents, generated)
}

func reconcileDocuments(root string, update bool, before, generated map[string]string) error {
	changed := changedDocuments(before, generated)
	if len(changed) == 0 {
		fmt.Println("Configured command transcripts are up to date.")
		return nil
	}
	for _, document := range changed {
		fmt.Printf("--- %s (checked-in)\n+++ %s (generated)\n", document, document)
		fmt.Print(unifiedDiff(before[document], generated[document]))
	}
	if !update {
		return fmt.Errorf("%d transcript document(s) are stale; run make update-transcripts to review and update them", len(changed))
	}
	return writeDocuments(root, changed, generated)
}

type fixtureBatch struct {
	indices []int
}

func runInvocations(root, evidencePath string, items []invocation, workerLimit int, run func(invocation) (commandResult, error)) ([]commandResult, error) {
	results := make([]commandResult, len(items))
	if len(items) == 0 {
		return results, nil
	}
	if workerLimit < 1 {
		return nil, errors.New("transcript worker limit must be positive")
	}

	batches := make([]fixtureBatch, 0, len(items))
	batchByPath := make(map[string]int, len(items))
	for i, item := range items {
		path, err := invocationFixturePath(root, evidencePath, item)
		if err != nil {
			return nil, err
		}
		batchIndex, exists := batchByPath[path]
		if !exists {
			batchIndex = len(batches)
			batchByPath[path] = batchIndex
			batches = append(batches, fixtureBatch{})
		}
		batches[batchIndex].indices = append(batches[batchIndex].indices, i)
	}

	workerCount := min(workerLimit, len(batches))
	jobs := make(chan fixtureBatch, len(batches))
	for _, batch := range batches {
		jobs <- batch
	}
	close(jobs)

	invocationErrors := make([]error, len(items))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for batch := range jobs {
				for _, index := range batch.indices {
					result, err := run(items[index])
					results[index] = result
					invocationErrors[index] = err
					if err != nil {
						break
					}
				}
			}
		}()
	}
	workers.Wait()

	failures := make([]error, 0)
	for _, err := range invocationErrors {
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	return results, nil
}

func invocationFixturePath(root, evidencePath string, item invocation) (string, error) {
	if !isMavenCommand(item.Command) {
		return "command:" + item.ID, nil
	}

	workingDirectory, err := resolveDirectory(root, item.WorkingDirectory)
	if err != nil {
		return "", err
	}
	file, found, err := mavenFileArgument(expandArgs(item.Args, root, evidencePath))
	if err != nil {
		return "", fmt.Errorf("transcript %s: %w", item.ID, err)
	}
	if !found {
		file = "pom.xml"
	}
	if !filepath.IsAbs(file) {
		file = filepath.Join(workingDirectory, file)
	}
	file, err = safeRepositoryPath(root, file)
	if err != nil {
		return "", err
	}
	file, err = canonicalizeMavenFilePath(file)
	if err != nil {
		return "", fmt.Errorf("transcript %s: resolve Maven fixture path: %w", item.ID, err)
	}
	return safeRepositoryPath(root, file)
}

func canonicalizeMavenFilePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect path %q: %w", absolute, err)
		}
		return absolute, nil
	}
	if info.IsDir() {
		return filepath.Join(absolute, "pom.xml"), nil
	}
	return absolute, nil
}

func isMavenCommand(command string) bool {
	name := strings.ToLower(filepath.Base(command))
	return name == "mvn" || name == "mvnw" || name == "mvn.cmd" || name == "mvnw.cmd"
}

func mavenFileArgument(args []string) (string, bool, error) {
	file := ""
	found := false
	setFile := func(value string) error {
		if found {
			return errors.New("Maven invocation contains multiple -f/--file arguments")
		}
		if value == "" {
			return errors.New("Maven invocation has an empty -f/--file argument")
		}
		file = value
		found = true
		return nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-f" || arg == "--file":
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("Maven invocation has %s without a fixture path", arg)
			}
			i++
			if err := setFile(args[i]); err != nil {
				return "", false, err
			}
		case strings.HasPrefix(arg, "-f="):
			if err := setFile(strings.TrimPrefix(arg, "-f=")); err != nil {
				return "", false, err
			}
		case strings.HasPrefix(arg, "--file="):
			if err := setFile(strings.TrimPrefix(arg, "--file=")); err != nil {
				return "", false, err
			}
		}
	}
	return file, found, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("transcript manifest contains trailing JSON values")
		}
		return fmt.Errorf("read end of transcript manifest: %w", err)
	}
	return nil
}

func validateManifest(config manifest) error {
	if config.SchemaVersion != 1 {
		return fmt.Errorf("unsupported transcript manifest schemaVersion %d; expected 1", config.SchemaVersion)
	}
	if len(config.Invocations) == 0 {
		return errors.New("transcript manifest must configure at least one invocation")
	}
	if config.Setup.Command == "" || config.Setup.EvidencePathMarker == "" {
		return errors.New("transcript setup command and evidencePathMarker are required")
	}
	seen := make(map[string]struct{}, len(config.Invocations))
	for _, item := range config.Invocations {
		if !markerID.MatchString(item.ID) {
			return fmt.Errorf("invalid transcript id %q", item.ID)
		}
		if _, exists := seen[item.ID]; exists {
			return fmt.Errorf("duplicate transcript id %q", item.ID)
		}
		seen[item.ID] = struct{}{}
		if item.TargetDocument == "" || item.WorkingDirectory == "" || item.Command == "" || item.Goal == "" {
			return fmt.Errorf("transcript %s is missing targetDocument, workingDirectory, command, or goal", item.ID)
		}
		if item.RenderMode != "" && item.RenderMode != "command-output" {
			return fmt.Errorf("transcript %s has unsupported renderMode %q", item.ID, item.RenderMode)
		}
		if item.ExpectedExitCode != 0 {
			return fmt.Errorf("transcript %s has nonzero expectedExitCode %d; documentation invocations must succeed", item.ID, item.ExpectedExitCode)
		}
		if item.MaxGraphRows < 0 {
			return fmt.Errorf("transcript %s has negative maxGraphRows", item.ID)
		}
		for _, required := range item.RequiredOutput {
			if strings.TrimSpace(required) == "" {
				return fmt.Errorf("transcript %s has an empty requiredOutput entry", item.ID)
			}
		}
	}
	return nil
}

func prepareEvidence(root string, setup setupCommand) (string, error) {
	dir, err := resolveDirectory(root, setup.WorkingDirectory)
	if err != nil {
		return "", err
	}
	result, err := runCommand(root, dir, setup.Command, setup.Args, setup.Environment)
	if err != nil {
		return "", fmt.Errorf("run transcript setup command: %w", err)
	}
	if result.ExitCode != setup.ExpectedExitCode {
		return "", fmt.Errorf("setup command exited %d, expected %d; full output follows:\n%s", result.ExitCode, setup.ExpectedExitCode, result.Output)
	}
	marker := setup.EvidencePathMarker
	var evidence string
	for _, line := range strings.Split(result.Output, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			candidate := strings.TrimSpace(line[i+len(marker):])
			if evidence != "" {
				return "", fmt.Errorf("setup output contains multiple evidence paths; full output follows:\n%s", result.Output)
			}
			evidence = candidate
		}
	}
	if evidence == "" {
		return "", fmt.Errorf("setup output did not contain evidence path marker %q; full output follows:\n%s", marker, result.Output)
	}
	evidence, err = filepath.Abs(evidence)
	if err != nil {
		return "", fmt.Errorf("resolve example evidence path %q: %w", evidence, err)
	}
	allowedPrefix := filepath.Join(root, ".scratch", "maven-dependency-elider-examples.")
	if !strings.HasPrefix(evidence, allowedPrefix) {
		return "", fmt.Errorf("setup evidence path %q is outside the expected .scratch fixture directory", evidence)
	}
	info, err := os.Stat(evidence)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("setup evidence path %q is not a directory", evidence)
	}
	return evidence, nil
}

func runInvocation(root, evidencePath string, item invocation) (commandResult, error) {
	dir, err := resolveDirectory(root, item.WorkingDirectory)
	if err != nil {
		return commandResult{}, err
	}
	args := invocationArgs(item.Args, root, evidencePath)
	result, err := runCommand(root, dir, item.Command, args, nil)
	if err != nil {
		return commandResult{}, fmt.Errorf("run transcript %s: %w", item.ID, err)
	}
	if result.ExitCode != item.ExpectedExitCode {
		return commandResult{}, fmt.Errorf("transcript %s exited %d, expected %d; full output follows:\n%s", item.ID, result.ExitCode, item.ExpectedExitCode, result.Output)
	}
	selected, found := selectGoalOutput(result.Output, item.Goal)
	if !found {
		return commandResult{}, fmt.Errorf("transcript %s output did not contain its %q Maven goal section; full output follows:\n%s", item.ID, item.Goal, result.Output)
	}
	for _, required := range item.RequiredOutput {
		if !strings.Contains(selected, required) {
			return commandResult{}, fmt.Errorf("transcript %s output did not contain required evidence %q; full output follows:\n%s", item.ID, required, result.Output)
		}
	}
	return commandResult{Output: selected, ExitCode: result.ExitCode}, nil
}

func invocationArgs(args []string, root, evidencePath string) []string {
	expanded := expandArgs(args, root, evidencePath)
	localRepository := filepath.Join(evidencePath, "maven-repository")
	return append([]string{"-Dmaven.repo.local=" + localRepository}, expanded...)
}

func runCommand(root, dir, command string, args []string, extraEnvironment map[string]string) (commandResult, error) {
	if strings.ContainsRune(command, filepath.Separator) && !filepath.IsAbs(command) {
		command = filepath.Join(root, command)
	}
	cmd := exec.Command(command, args...)
	cmd.Dir = dir
	cmd.Env = mergedEnvironment(extraEnvironment)
	reader, writer, err := os.Pipe()
	if err != nil {
		return commandResult{}, fmt.Errorf("create command output pipe: %w", err)
	}
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Start(); err != nil {
		writer.Close()
		reader.Close()
		return commandResult{}, fmt.Errorf("start %s: %w", command, err)
	}
	if err := writer.Close(); err != nil {
		reader.Close()
		return commandResult{}, fmt.Errorf("close parent command output pipe: %w", err)
	}
	outputBytes, readErr := io.ReadAll(reader)
	reader.Close()
	waitErr := cmd.Wait()
	if readErr != nil {
		return commandResult{Output: string(outputBytes), ExitCode: -1}, fmt.Errorf("read output from %s: %w", command, readErr)
	}
	output := string(outputBytes)
	code := 0
	if waitErr != nil {
		var exitError *exec.ExitError
		if errors.As(waitErr, &exitError) {
			code = exitError.ExitCode()
		} else {
			return commandResult{Output: output, ExitCode: -1}, fmt.Errorf("wait for %s: %w", command, waitErr)
		}
	}
	return commandResult{Output: output, ExitCode: code}, nil
}

func mergedEnvironment(extra map[string]string) []string {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, found := strings.Cut(entry, "=")
		if found {
			values[key] = value
		}
	}
	for key, value := range extra {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func resolveDirectory(root, directory string) (string, error) {
	path := directory
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve working directory %q: %w", directory, err)
	}
	return safeRepositoryPath(root, path)
}

func safeRepositoryPath(root, path string) (string, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve repository path %q: %w", path, err)
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the repository root", path)
	}
	return absolute, nil
}

func expandArgs(args []string, root, evidencePath string) []string {
	result := make([]string, len(args))
	for i, arg := range args {
		arg = strings.ReplaceAll(arg, "{root}", root)
		arg = strings.ReplaceAll(arg, "{evidence}", evidencePath)
		result[i] = arg
	}
	return result
}

func renderCommand(item invocation) string {
	parts := make([]string, 0, len(item.Args)+1)
	parts = append(parts, item.Command)
	for _, arg := range item.Args {
		arg = strings.ReplaceAll(arg, "{root}", "$PROJECT_ROOT")
		arg = strings.ReplaceAll(arg, "{evidence}", "$TRANSCRIPT_EVIDENCE")
		parts = append(parts, shellQuote(arg))
	}
	if len(parts) <= 4 {
		return "$ " + strings.Join(parts, " ")
	}
	var command strings.Builder
	command.WriteString("$ ")
	command.WriteString(parts[0])
	command.WriteString(" \\\n")
	for i, part := range parts[1:] {
		command.WriteString("  ")
		command.WriteString(part)
		if i < len(parts)-2 {
			command.WriteString(" \\\n")
		}
	}
	return command.String()
}

func shellQuote(value string) string {
	if safeArg.MatchString(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func selectGoalOutput(output, goal string) (string, bool) {
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	foundGoal := false
	selected := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "[INFO] --- ") && strings.Contains(line, ":"+goal+" (") {
			foundGoal = true
		}
		line = strings.TrimRight(line, "\r")
		if line == "[INFO] Scanning for projects..." || line == "[INFO] BUILD SUCCESS" || line == "[INFO] BUILD FAILURE" || line == "[INFO] BUILD FAILED" {
			continue
		}
		selected = append(selected, line)
	}
	return strings.Join(selected, "\n"), foundGoal
}

func normalizeOutput(output, root, evidencePath string) []string {
	root = filepath.ToSlash(filepath.Clean(root))
	evidencePath = filepath.ToSlash(filepath.Clean(evidencePath))
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.ReplaceAll(line, evidencePath, "<TEMP_DIR>")
		line = strings.ReplaceAll(line, root, "<PROJECT_ROOT>")
		line = snapshotAt.ReplaceAllString(line, "${1}<TIMESTAMP>")
		line = buildTime.ReplaceAllString(line, "${1} <BUILD_TIME>")
		line = finishedAt.ReplaceAllString(line, "${1} <TIMESTAMP>")
		line = cacheHitTime.ReplaceAllString(line, "maximum validated hit <CACHE_HIT_TIME>")
		line = processID.ReplaceAllString(line, "${1}${2}<PID>")
		line = strings.TrimRight(line, " \t")
		result = append(result, line)
	}
	return result
}

func elideGraphRows(lines []string, limit int) []string {
	header := "Mediated TEST dependency graph (captured and saved by the elide goal):"
	inside := false
	seen := 0
	omitted := make([]string, 0)
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, header) {
			inside = true
			result = append(result, line)
			continue
		}
		if inside && strings.HasPrefix(line, "[INFO]   - ") {
			if seen < limit {
				result = append(result, line)
				seen++
			} else {
				omitted = append(omitted, line)
			}
			continue
		}
		if inside && len(omitted) > 0 {
			result = append(result, graphOmission(omitted))
			omitted = omitted[:0]
		}
		inside = false
		result = append(result, line)
	}
	if len(omitted) > 0 {
		result = append(result, graphOmission(omitted))
	}
	return result
}

func graphOmission(lines []string) string {
	content := strings.Join(lines, "\n") + "\n"
	digest := sha256.Sum256([]byte(content))
	return fmt.Sprintf("[INFO]   ... %d dependency graph rows elided (sha256:%s)", len(lines), hex.EncodeToString(digest[:]))
}

func replaceBlocks(content string, items []invocation, outputs map[string]string) (string, error) {
	type block struct {
		item  invocation
		start int
		end   int
	}
	blocks := make([]block, 0, len(items))
	for _, item := range items {
		begin := "<!-- BEGIN:transcript:" + item.ID + " -->"
		end := "<!-- END:transcript:" + item.ID + " -->"
		beginAt := strings.Index(content, begin)
		endAt := strings.Index(content, end)
		if beginAt < 0 || endAt < 0 || strings.Index(content[beginAt+len(begin):], begin) >= 0 || strings.Index(content[endAt+len(end):], end) >= 0 || endAt < beginAt {
			return "", fmt.Errorf("expected exactly one ordered BEGIN/END marker pair for %s", item.ID)
		}
		blocks = append(blocks, block{item: item, start: beginAt, end: endAt + len(end)})
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i].start < blocks[j].start })
	for i := 1; i < len(blocks); i++ {
		if blocks[i].start < blocks[i-1].end {
			return "", fmt.Errorf("transcript marker regions overlap: %s and %s", blocks[i-1].item.ID, blocks[i].item.ID)
		}
	}
	for i := len(blocks) - 1; i >= 0; i-- {
		block := blocks[i]
		begin := "<!-- BEGIN:transcript:" + block.item.ID + " -->"
		end := "<!-- END:transcript:" + block.item.ID + " -->"
		body := "\n\n```text\n" + outputs[block.item.ID] + "\n```\n\n"
		replacement := begin + body + end
		content = content[:block.start] + replacement + content[block.end:]
	}
	return content, nil
}

func changedDocuments(before, after map[string]string) []string {
	changed := make([]string, 0)
	for path, content := range before {
		if content != after[path] {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}

func unifiedDiff(before, after string) string {
	oldLines := strings.Split(before, "\n")
	newLines := strings.Split(after, "\n")
	rows, cols := len(oldLines)+1, len(newLines)+1
	lcs := make([][]int, rows)
	for i := range lcs {
		lcs[i] = make([]int, cols)
	}
	for i := len(oldLines) - 1; i >= 0; i-- {
		for j := len(newLines) - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var diff strings.Builder
	i, j := 0, 0
	for i < len(oldLines) || j < len(newLines) {
		if i < len(oldLines) && j < len(newLines) && oldLines[i] == newLines[j] {
			i++
			j++
		} else if i < len(oldLines) && (j == len(newLines) || lcs[i+1][j] >= lcs[i][j+1]) {
			diff.WriteString("-")
			diff.WriteString(oldLines[i])
			diff.WriteByte('\n')
			i++
		} else {
			diff.WriteString("+")
			diff.WriteString(newLines[j])
			diff.WriteByte('\n')
			j++
		}
	}
	return diff.String()
}

func writeDocuments(root string, paths []string, documents map[string]string) error {
	tempFiles := make(map[string]string, len(paths))
	cleanup := func() {
		for _, path := range tempFiles {
			_ = os.Remove(path)
		}
	}
	defer cleanup()
	for _, document := range paths {
		path, err := safeRepositoryPath(root, document)
		if err != nil {
			return err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".transcript-update-*.tmp")
		if err != nil {
			return fmt.Errorf("create temporary transcript file for %s: %w", document, err)
		}
		tempFiles[document] = file.Name()
		if _, err := file.WriteString(documents[document]); err != nil {
			file.Close()
			return fmt.Errorf("write temporary transcript file for %s: %w", document, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close temporary transcript file for %s: %w", document, err)
		}
		info, err := os.Stat(path)
		if err == nil {
			if err := os.Chmod(file.Name(), info.Mode().Perm()); err != nil {
				return fmt.Errorf("preserve permissions for %s: %w", document, err)
			}
		}
	}
	for _, document := range paths {
		path, _ := safeRepositoryPath(root, document)
		if err := os.Rename(tempFiles[document], path); err != nil {
			return fmt.Errorf("replace transcript document %s: %w", document, err)
		}
		delete(tempFiles, document)
	}
	for _, document := range paths {
		fmt.Printf("Updated %s\n", document)
	}
	return nil
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "update-transcripts:", message)
	os.Exit(1)
}
