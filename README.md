# Josh_Test - Splunk Detection Content Pack

Custom Splunk detection content pack with a CI/CD pipeline. Write detections as `.conf` files, push to `main`, and a versioned app `.tgz` is automatically built.

---

## Directory Structure

```
detections/          <- saved search .conf files (one per detection)
macros/              <- macro .conf files
lookups/             <- lookup CSV files
app_template/        <- static app files (metadata, icons, nav, views)
app_build.yml        <- app metadata (name, version, author)
build.py             <- build script (assembles the app)
.github/workflows/   <- GitHub Actions workflow
```

---

## Adding a Detection

1. Create a new `.conf` file in `detections/` (e.g. `my_detection.conf`)
2. Write your saved search stanza in standard Splunk conf format:

```ini
[My Detection Name]
search = index=main sourcetype=foo | stats count by dest
cron_schedule = 0 * * * *
dispatch.earliest_time = -70m@m
dispatch.latest_time = -10m@m
action.risk = 1
action.risk.param._risk = [{"risk_object_field": "dest", "risk_object_type": "system", "risk_score": 60}]
action.risk.param._risk_message = Something happened on $dest$
enableSched = 1
alert.track = 1
```

3. Push to `main` -- the pipeline builds automatically

All `.conf` files in `detections/` are concatenated into `savedsearches.conf` in the built app. Files are processed in alphabetical order by filename.

---

## Adding a Macro

Same pattern as detections. Create a `.conf` file in `macros/`:

```ini
[my_macro(field)]
definition = where $field$!=""
```

All macro `.conf` files get concatenated into `macros.conf`.

---

## Adding Lookups

Drop `.csv` files into `lookups/`. They get copied into the app's `lookups/` directory at build time.

---

## Versioning

Version format: `major.minor.patch`

- **Major.minor** -- set manually in `app_build.yml`
- **Patch** -- auto-increments based on git commit count (no action needed)

Example: if `app_build.yml` has `version: "0.0"` and you have 12 commits, the built app is `0.0.12`.

### Bumping Major or Minor

Edit `app_build.yml` and change the version:

```yaml
app:
  version: "0.1"   # was "0.0", now minor bumped to 1
```

Push to `main`. Patch resets relative to the new base (it's still the commit count, but the minor change is what matters).

---

## CI/CD Pipeline

- Push to `main` triggers the GitHub Action
- The action runs `build.py`, which assembles the Splunk app
- A versioned artifact is uploaded (e.g. `Josh_Test_0.0.12`)
- The artifact contains the `.tgz` (deploy this) and the extracted app directory (inspect this)

### What Triggers a Build

Only changes to these paths trigger the workflow:

- `detections/`
- `macros/`
- `lookups/`
- `app_template/`
- `app_build.yml`

Changes to `README.md`, `build.py`, or `.github/` do **not** trigger a build.

---

## App Metadata

Edit `app_build.yml` to change app-level settings:

```yaml
app:
  uid: 37057
  title: Josh_Test        # app title
  appid: Josh_Test        # app ID (folder name inside .tgz -- don't change after first deploy)
  version: "0.0"          # major.minor only, patch is automatic
  description: This is an app
  author_name: Josh
  author_email: Josh
  author_company: author company
```
