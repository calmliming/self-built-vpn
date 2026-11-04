"""Build the dependency-free, single-file HTML prototype."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
source = ROOT / "src"
output = ROOT / "dist"
output.mkdir(exist_ok=True)
html = (source / "index.html").read_text()
css = (source / "styles.css").read_text()
js = (source / "app.js").read_text()
assert "</style" not in css.lower()
assert "</script" not in js.lower()
html = html.replace('<link rel="stylesheet" href="styles.css">', "<style>\n" + css + "\n</style>")
html = html.replace('<script src="app.js"></script>', "<script>\n" + js + "\n</script>")
(output / "index.html").write_text(html)
print(output / "index.html")
