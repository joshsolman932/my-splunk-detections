"""
Splunk app build script.

Assembles detections, macros, and app_template into a packaged .tgz app.
Output goes to dist/:
  dist/Josh_Test_0.0.3/      <- assembled app (inspect this)
  dist/Josh_Test_0.0.3.tgz   <- packaged app (deploy this)

Version: major.minor from app_build.yml, patch from git commit count.
"""
import os
import glob
import shutil
import tarfile
import subprocess
import yaml

APP_BUILD_YML   = "app_build.yml"
APP_TEMPLATE    = "app_template"
DETECTIONS_DIR  = "detections"
MACROS_DIR      = "macros"
LOOKUPS_DIR     = "lookups"
DASHBOARDS_DIR  = "dashboards"
DIST_DIR        = "dist"


def get_patch_version():
    """Get patch number from git commit count, or 0 if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, check=True
        )
        return int(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return 0


def get_version(app):
    """Build full version: major.minor from contentctl.yml, patch from git."""
    base = str(app.get("version", "0.0"))
    parts = base.split(".")
    major = parts[0] if len(parts) > 0 else "0"
    minor = parts[1] if len(parts) > 1 else "0"
    patch = get_patch_version()
    return f"{major}.{minor}.{patch}"


def generate_app_conf(app, version):
    """Generate default/app.conf from contentctl.yml app block."""
    return (
        "[install]\n"
        "build = 1\n"
        "is_configured = 0\n"
        "state = enabled\n"
        "\n"
        "[ui]\n"
        "is_visible = 1\n"
        f"label = {app.get('title', app['appid'])}\n"
        "\n"
        "[launcher]\n"
        f"author = {app.get('author_name', '')}\n"
        f"description = {app.get('description', '')}\n"
        f"version = {version}\n"
        "\n"
        "[id]\n"
        f"name = {app['appid']}\n"
        f"version = {version}\n"
    )


def concat_conf_files(directory):
    """Concatenate all .conf files in a directory into a single string."""
    conf_files = sorted(glob.glob(os.path.join(directory, "**", "*.conf"), recursive=True))
    if not conf_files:
        return None
    stanzas = []
    for path in conf_files:
        with open(path) as f:
            stanzas.append(f.read().strip())
    return "\n\n".join(stanzas) + "\n"


def strip_gitkeeps(directory):
    """Remove .gitkeep files and any directories they leave empty."""
    for path in glob.glob(os.path.join(directory, "**", ".gitkeep"), recursive=True):
        os.remove(path)
    for dirpath, _, filenames in os.walk(directory, topdown=False):
        if not os.listdir(dirpath) and dirpath != directory:
            try:
                os.rmdir(dirpath)
            except OSError:
                pass


def main():
    with open(APP_BUILD_YML) as f:
        config = yaml.safe_load(f)

    app     = config["app"]
    appid   = app["appid"]
    version = get_version(app)
    name    = f"{appid}_{version}"

    app_dir     = os.path.join(DIST_DIR, name)
    default_dir = os.path.join(app_dir, "default")

    # Clean previous build (ignore_errors for Windows file locking)
    if os.path.exists(app_dir):
        shutil.rmtree(app_dir, ignore_errors=True)
    os.makedirs(default_dir, exist_ok=True)

    # --- Copy app_template into the app ---
    if os.path.exists(APP_TEMPLATE):
        for item in ["metadata", "static", "README", "lookups"]:
            src = os.path.join(APP_TEMPLATE, item)
            if os.path.exists(src):
                shutil.copytree(src, os.path.join(app_dir, item), dirs_exist_ok=True)
        # default/data/ (nav, views, etc.)
        src_data = os.path.join(APP_TEMPLATE, "default", "data")
        if os.path.exists(src_data):
            shutil.copytree(src_data, os.path.join(default_dir, "data"), dirs_exist_ok=True)

    # --- Copy any lookup files from root lookups/ ---
    if os.path.exists(LOOKUPS_DIR):
        dst = os.path.join(app_dir, "lookups")
        os.makedirs(dst, exist_ok=True)
        for item in glob.glob(os.path.join(LOOKUPS_DIR, "*")):
            if os.path.isfile(item):
                shutil.copy2(item, dst)

    # --- Copy dashboard XMLs into default/data/ui/views/ ---
    if os.path.exists(DASHBOARDS_DIR):
        views_dir = os.path.join(default_dir, "data", "ui", "views")
        os.makedirs(views_dir, exist_ok=True)
        for item in glob.glob(os.path.join(DASHBOARDS_DIR, "*.xml")):
            shutil.copy2(item, views_dir)

    # --- Generate conf files ---
    with open(os.path.join(default_dir, "app.conf"), "w") as f:
        f.write(generate_app_conf(app, version))

    saved_searches = concat_conf_files(DETECTIONS_DIR)
    if saved_searches:
        with open(os.path.join(default_dir, "savedsearches.conf"), "w") as f:
            f.write(saved_searches)

    macros = concat_conf_files(MACROS_DIR)
    if macros:
        with open(os.path.join(default_dir, "macros.conf"), "w") as f:
            f.write(macros)

    # --- Clean up .gitkeep artifacts ---
    strip_gitkeeps(app_dir)

    # --- Package as .tgz (arcname=appid so Splunk sees the right app name) ---
    tgz_path = os.path.join(DIST_DIR, f"{name}.tgz")
    with tarfile.open(tgz_path, "w:gz") as tar:
        tar.add(app_dir, arcname=appid)

    print(f"Version: {version}")
    print(f"Built: {tgz_path}")
    print(f"Extracted app: {app_dir}")


if __name__ == "__main__":
    main()
