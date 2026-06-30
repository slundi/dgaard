# How to Contribute to this Project

Thank you for your interest in contributing to this project! Your help is invaluable in making it better.

Please follow the guidelines below to submit your contributions effectively.

## Submitting Your Changes via Merge Requests

For any changes you wish to make to the project (bug fixes, feature additions, documentation improvements, etc.), please follow the **Merge Request** process (or Pull Request if you are using another source code management tool like GitHub).

Here are the steps to follow:

1. **Fork the repository (if you are not a direct collaborator).** Create a copy of the repository on your own account.
2. **Create a dedicated branch for your modification.** Give your branch a clear and descriptive name of the feature or fix you are implementing (e.g., `fix-login-bug`, `feat-new-feature`).
   ```bash
   git checkout -b my-descriptive-branch
   ```
3. **Make your changes and commit them.** Ensure you follow the Conventional Commits convention (see the section below).
4. **Push your branch to your fork (or the main repository if you are a collaborator).**
   ```bash
   git push origin my-descriptive-branch
   ```
5. **Create a Merge Request (or Pull Request).** From your source code management interface (e.g., GitLab, GitHub), create a new Merge Request.
   - **Source Branch:** Select the branch you just pushed.
   - **Target Branch:** Select the main branch of the project (usually `main` or `master`).
   - **Title:** Give your Merge Request a clear and concise title that summarizes your change. Also, use the Conventional Commits convention for the title.
   - **Description:** Provide a detailed description of your modification. Explain the problem you are solving, the feature you are adding, or the improvement you are making. Include steps to test your changes if necessary.
   - **Assign a reviewer (if applicable).**
   - **Add labels (if applicable).**

## Types

### Included in changelog

Those types will be included in the changelog because user may want to know.

- `feat` for new feature
- `fix` for bug fix only when there is an issue created on the repository, if no issue it is a `chore`

### Never included in changelog

- `build`, `chore`, `ci`, `refactor`, `test`

### Unsure

- `docs`: depending if users are complaining or often asking the same thing.
- `perf`: may be relevant for user with big networks

The project team will review your Merge Request, may ask for clarifications or modifications, and will merge it once it is approved.

## Using the Conventional Commits Convention

We adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification to maintain a clear and structured commit history. This makes it easier to understand changes and automate certain processes (like generating changelogs).

A commit should be structured as follows:

## Operational: Updating the compiled-in root-server hints

The iterative recursive resolver ships with a snapshot of the 13 IANA
root-server addresses (`ROOT_HINTS_V4` + `ROOT_HINTS_V6` in
`dgaard/src/dns/recursive.rs`). Real-world drift is rare — measured in
years — but happens (e.g. B-root's 2017 address change). A weekly
Woodpecker cron downloads `https://www.internic.net/domain/named.root`
and runs `just check-root-hints`; the build fails as soon as the
upstream file disagrees with the compiled-in arrays.

When that happens:

1. Run the check locally to reproduce:

   ```bash
   just check-root-hints
   ```

   The failure output lists each drifted operator and family, e.g.:

   ```
   AAAA g: drift — compiled=2001:500:12::d upstream=2001:500:12::d0d
   ```

2. Open `dgaard/src/dns/recursive.rs` and update the affected entry of
   `ROOT_HINTS_V4` (for `A` drift lines) or `ROOT_HINTS_V6` (for `AAAA`
   lines). The order of letters inside the arrays does not matter —
   the resolver picks at random — so keep the alphabetical layout
   that already exists.

3. Re-run `just check-root-hints` until it passes. Then run the unit
   tests to confirm nothing else regressed:

   ```bash
   just test
   ```

4. Commit with a `chore(roots):` prefix referencing the change in
   IANA's `named.root`. Include the upstream URL and the date the
   check started failing in the commit body so future archaeologists
   can audit the drift trail.

The `fixture_named_root()` helper in the unit tests is the
_operational shadow_ of the production constants; if you change the
constants, update the fixture so the round-trip diff stays empty.
