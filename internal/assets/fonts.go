package assets

import _ "embed"

// NotoSansRegular and NotoSansBold provide Cyrillic glyph coverage for PDF
// generation (internal/report). Sourced from the Noto Sans font already
// bundled with fyne.io/fyne for GUI rendering; Apache License 2.0, see
// fonts/LICENSE-NotoSans.txt.

//go:embed fonts/NotoSans-Regular.ttf
var NotoSansRegular []byte

//go:embed fonts/NotoSans-Bold.ttf
var NotoSansBold []byte
