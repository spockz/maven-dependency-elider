# RQ-0006: Maven Plugin Documentation Site and GitHub Pages Publishing

## Status

Open

## Research question

Should this project generate its Maven plugin documentation site with Maven's site tooling and publish the generated static site through GitHub Actions and GitHub Pages?

## Context

The project is a Maven plugin. Maven's plugin report tooling can generate an overview and goal reference pages from the plugin descriptor and Mojo documentation. Maven Site can combine those generated reports with hand-written guides into a static site. GitHub Actions and GitHub Pages can publish static build output, so Maven's `site-deploy` goal is not necessarily needed.

The project already maintains user and contributor documentation in the repository. A plugin site may provide a discoverable home for installation instructions, goal and parameter references, configuration examples, troubleshooting, and links to the fuller repository documentation.

## Options to evaluate

1. Keep documentation in the repository only, without generating or publishing a site.
2. Generate a Maven site locally or in CI, but do not publish it.
3. Generate the site with Maven and publish `target/site/` using a GitHub Actions workflow and GitHub Pages.
4. Generate and deploy the site using Maven's `site-deploy` goal and configured site distribution.

## Questions to answer

- Which existing documentation belongs on the user-facing plugin site, and which material should remain contributor-only?
- Can Maven Plugin Report generate accurate goal and parameter pages from the plugin's descriptor and Mojo documentation?
- Which hand-written pages are needed for installation, configuration, usage examples, dependency-tree behavior, and troubleshooting?
- Should the published site represent the default branch, tagged releases, or both?
- How should GitHub Actions build the site, preserve versioned documentation if needed, and publish it to GitHub Pages?
- Is there any practical reason to use Maven `site-deploy` instead of letting GitHub Actions publish the static output?
- What checks should prevent publishing broken links, missing generated goal pages, or stale documentation?

## Decision criteria

- Documentation accuracy and synchronization with plugin goals and parameters.
- Ease of finding current user guidance and contributor guidance.
- Reproducibility of site generation in CI.
- Clear relationship between the site version and released plugin versions.
- Minimal additional build and maintenance complexity.

## Expected outcome

Recommend whether to add site generation and publication, identify the pages and generated reports to include, and specify the CI publishing trigger and versioning policy. The recommendation should distinguish Maven site generation from deployment: publishing static output through GitHub Actions may make Maven `site-deploy` unnecessary.
