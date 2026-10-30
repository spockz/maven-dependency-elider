// WHY: Protects fixture scheduling, stable result ordering, and the transcript writer's update-only contract.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInvocationFixturePathUsesMavenFileArgument(t *testing.T) {
	root := t.TempDir()
	first := invocation{
		ID:               "first",
		WorkingDirectory: ".",
		Command:          "./mvnw",
		Args:             []string{"-f", "examples/first/pom.xml"},
	}
	sameFixture := invocation{
		ID:               "same-fixture",
		WorkingDirectory: ".",
		Command:          "./mvnw",
		Args:             []string{"-f=./examples/first/pom.xml"},
	}
	second := invocation{
		ID:               "second",
		WorkingDirectory: ".",
		Command:          "./mvnw",
		Args:             []string{"-f", "examples/second/pom.xml"},
	}

	firstPath, err := invocationFixturePath(root, "", first)
	if err != nil {
		t.Fatal(err)
	}
	sameFixturePath, err := invocationFixturePath(root, "", sameFixture)
	if err != nil {
		t.Fatal(err)
	}
	secondPath, err := invocationFixturePath(root, "", second)
	if err != nil {
		t.Fatal(err)
	}
	if firstPath != sameFixturePath {
		t.Fatalf("equivalent Maven -f paths produced different fixture keys: %q and %q", firstPath, sameFixturePath)
	}
	if firstPath == secondPath {
		t.Fatalf("different Maven -f paths shared a fixture key: %q", firstPath)
	}
	for _, flag := range []string{"-fae", "-ff", "-fn"} {
		withFailMode := first
		withFailMode.Args = append([]string{flag}, first.Args...)
		path, err := invocationFixturePath(root, "", withFailMode)
		if err != nil {
			t.Fatalf("Maven fail-mode flag %q changed fixture parsing: %v", flag, err)
		}
		if path != firstPath {
			t.Errorf("Maven fail-mode flag %q changed fixture key from %q to %q", flag, firstPath, path)
		}
	}
}

func TestRunInvocationsBoundsWorkersAndPreservesFixtureOrder(t *testing.T) {
	root := t.TempDir()
	items := []invocation{
		fixtureInvocation("first-basic", "examples/basic/pom.xml"),
		fixtureInvocation("cve", "examples/cve/pom.xml"),
		fixtureInvocation("spring", "examples/spring/pom.xml"),
		fixtureInvocation("second-basic", "./examples/basic/pom.xml"),
		fixtureInvocation("safe", "examples/safe/pom.xml"),
	}
	release := make(chan struct{})
	started := make(chan string, len(items))
	done := make(chan invocationRun, 1)
	var mu sync.Mutex
	var active int
	var maximumActive int
	events := make([]invocationEvent, 0, len(items)*2)
	run := func(item invocation) (commandResult, error) {
		mu.Lock()
		active++
		if active > maximumActive {
			maximumActive = active
		}
		events = append(events, invocationEvent{kind: "start", id: item.ID})
		mu.Unlock()

		started <- item.ID
		<-release

		mu.Lock()
		events = append(events, invocationEvent{kind: "finish", id: item.ID})
		active--
		mu.Unlock()
		return commandResult{Output: item.ID}, nil
	}
	go func() {
		results, err := runInvocations(root, "", items, 2, run)
		done <- invocationRun{results: results, err: err}
	}()

	firstTwo := make([]string, 0, 2)
	for range 2 {
		select {
		case id := <-started:
			firstTwo = append(firstTwo, id)
		case <-time.After(time.Second):
			close(release)
			<-done
			t.Fatal("two fixture commands did not overlap")
		}
	}
	firstFixture, err := invocationFixturePath(root, "", findInvocation(t, items, firstTwo[0]))
	if err != nil {
		t.Fatal(err)
	}
	secondFixture, err := invocationFixturePath(root, "", findInvocation(t, items, firstTwo[1]))
	if err != nil {
		t.Fatal(err)
	}
	if firstFixture == secondFixture {
		t.Fatalf("worker pool started the same fixture concurrently: %v", firstTwo)
	}

	close(release)
	var result invocationRun
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture worker pool did not finish after release")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	mu.Lock()
	observedMaximum := maximumActive
	observedEvents := append([]invocationEvent(nil), events...)
	mu.Unlock()
	if observedMaximum != 2 {
		t.Fatalf("observed maximum concurrency %d, want 2", observedMaximum)
	}
	if got, want := resultIDs(result.results), []string{"first-basic", "cve", "spring", "second-basic", "safe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("results were not assembled in manifest order: got %v, want %v", got, want)
	}
	firstFinish := eventIndex(observedEvents, invocationEvent{kind: "finish", id: "first-basic"})
	secondStart := eventIndex(observedEvents, invocationEvent{kind: "start", id: "second-basic"})
	if firstFinish < 0 || secondStart < 0 || firstFinish >= secondStart {
		t.Fatalf("commands for one fixture were not sequential: events %v", observedEvents)
	}
}

func TestRunInvocationsReturnsManifestOrderAfterOutOfOrderCompletion(t *testing.T) {
	root := t.TempDir()
	items := []invocation{
		fixtureInvocation("slow", "examples/slow/pom.xml"),
		fixtureInvocation("fast", "examples/fast/pom.xml"),
	}
	releaseSlow := make(chan struct{})
	completed := make(chan string, len(items))
	done := make(chan invocationRun, 1)
	run := func(item invocation) (commandResult, error) {
		if item.ID == "slow" {
			<-releaseSlow
		}
		completed <- item.ID
		return commandResult{Output: item.ID}, nil
	}
	go func() {
		results, err := runInvocations(root, "", items, len(items), run)
		done <- invocationRun{results: results, err: err}
	}()

	select {
	case id := <-completed:
		if id != "fast" {
			close(releaseSlow)
			<-done
			t.Fatalf("completed %q while slow fixture was blocked, want fast fixture", id)
		}
	case <-time.After(time.Second):
		close(releaseSlow)
		<-done
		t.Fatal("fast fixture command did not complete while the first fixture was blocked")
	}
	close(releaseSlow)
	var result invocationRun
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("fixture worker pool did not finish after release")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if got, want := resultIDs(result.results), []string{"slow", "fast"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("results followed completion order instead of manifest order: got %v, want %v", got, want)
	}
}

func TestRunInvocationsReturnsEarliestManifestError(t *testing.T) {
	root := t.TempDir()
	items := []invocation{
		fixtureInvocation("first-error", "examples/first/pom.xml"),
		fixtureInvocation("second-error", "examples/second/pom.xml"),
	}
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	done := make(chan invocationRun, 1)
	run := func(item invocation) (commandResult, error) {
		if item.ID == "first-error" {
			close(firstStarted)
			<-releaseFirst
			return commandResult{}, errors.New("first manifest failure")
		}
		close(secondStarted)
		return commandResult{}, errors.New("second manifest failure")
	}
	go func() {
		results, err := runInvocations(root, "", items, len(items), run)
		done <- invocationRun{results: results, err: err}
	}()

	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		close(releaseFirst)
		<-done
		t.Fatal("first manifest invocation did not start")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		close(releaseFirst)
		<-done
		t.Fatal("second fixture error did not complete while the first was blocked")
	}
	close(releaseFirst)

	select {
	case result := <-done:
		if result.err == nil || result.err.Error() != "first manifest failure" {
			t.Fatalf("got error %v, want earliest manifest error", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("fixture worker pool did not return errors")
	}
}

func TestGenerateAndReconcileFailureDoesNotWriteDocuments(t *testing.T) {
	for _, update := range []bool{false, true} {
		mode := "check"
		if update {
			mode = "update"
		}
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			items := []invocation{
				fixtureInvocation("successful-fixture", "examples/success/pom.xml"),
				fixtureInvocation("failed-fixture", "examples/failure/pom.xml"),
			}
			items[0].TargetDocument = "README.md"
			items[1].TargetDocument = "usage.md"
			before := map[string]string{
				"README.md": "<!-- BEGIN:transcript:successful-fixture -->\nold transcript\n<!-- END:transcript:successful-fixture -->\n",
				"usage.md":  "<!-- BEGIN:transcript:failed-fixture -->\nold transcript\n<!-- END:transcript:failed-fixture -->\n",
			}
			modTimes := make(map[string]time.Time, len(before))
			for path, contents := range before {
				fullPath := filepath.Join(root, path)
				if err := os.WriteFile(fullPath, []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(fullPath)
				if err != nil {
					t.Fatal(err)
				}
				modTimes[path] = info.ModTime()
			}
			run := func(item invocation) (commandResult, error) {
				if item.ID == "failed-fixture" {
					return commandResult{}, errors.New("fixture command failed")
				}
				return commandResult{Output: "successful output"}, nil
			}

			err := generateAndReconcile(root, "", items, update, run)
			if err == nil || !strings.Contains(err.Error(), "fixture command failed") {
				t.Fatalf("got error %v, want fixture command failure", err)
			}
			for path, expected := range before {
				fullPath := filepath.Join(root, path)
				contents, err := os.ReadFile(fullPath)
				if err != nil {
					t.Fatal(err)
				}
				if string(contents) != expected {
					t.Errorf("%s mode changed %s after an invocation failure: got %q", mode, path, contents)
				}
				info, err := os.Stat(fullPath)
				if err != nil {
					t.Fatal(err)
				}
				if !info.ModTime().Equal(modTimes[path]) {
					t.Errorf("%s mode changed %s modification time after an invocation failure", mode, path)
				}
			}
		})
	}
}

func TestReconcileDocumentsCheckModeIsReadOnlyAndUpdateModeWrites(t *testing.T) {
	root := t.TempDir()
	before := map[string]string{
		"README.md": "old transcript\n",
		"usage.md":  "unchanged transcript\n",
	}
	generated := map[string]string{
		"README.md": "new transcript\n",
		"usage.md":  "unchanged transcript\n",
	}
	for path, contents := range before {
		if err := os.WriteFile(filepath.Join(root, path), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		contents, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return string(contents)
	}
	modTime := func(path string) time.Time {
		t.Helper()
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return info.ModTime()
	}
	readmeModTime := modTime("README.md")
	usageModTime := modTime("usage.md")

	err := reconcileDocuments(root, false, before, generated)
	if err == nil || !strings.Contains(err.Error(), "transcript document(s) are stale") {
		t.Fatalf("check mode returned %v, want stale transcript error", err)
	}
	if got := read("README.md"); got != before["README.md"] {
		t.Fatalf("check mode modified README.md: got %q", got)
	}
	if got := read("usage.md"); got != before["usage.md"] {
		t.Fatalf("check mode modified unchanged usage.md: got %q", got)
	}
	if got := modTime("README.md"); !got.Equal(readmeModTime) {
		t.Fatalf("check mode changed README.md modification time: got %s, want %s", got, readmeModTime)
	}
	if got := modTime("usage.md"); !got.Equal(usageModTime) {
		t.Fatalf("check mode changed usage.md modification time: got %s, want %s", got, usageModTime)
	}

	if err := reconcileDocuments(root, true, before, generated); err != nil {
		t.Fatal(err)
	}
	if got := read("README.md"); got != generated["README.md"] {
		t.Fatalf("update mode did not write generated README.md: got %q", got)
	}
	if got := read("usage.md"); got != before["usage.md"] {
		t.Fatalf("update mode rewrote unchanged usage.md: got %q", got)
	}
}

type invocationRun struct {
	results []commandResult
	err     error
}

type invocationEvent struct {
	kind string
	id   string
}

func fixtureInvocation(id, file string) invocation {
	return invocation{
		ID:               id,
		WorkingDirectory: ".",
		Command:          "./mvnw",
		Args:             []string{"-f", file},
	}
}

func findInvocation(t *testing.T, items []invocation, id string) invocation {
	t.Helper()
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("invocation %q not found", id)
	return invocation{}
}

func resultIDs(results []commandResult) []string {
	ids := make([]string, len(results))
	for i, result := range results {
		ids[i] = result.Output
	}
	return ids
}

func eventIndex(events []invocationEvent, expected invocationEvent) int {
	for i, event := range events {
		if event == expected {
			return i
		}
	}
	return -1
}
