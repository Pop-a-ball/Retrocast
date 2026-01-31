# Licenses and Attributions

## Project Ownership

All code, documentation, and configurations in this project, **unless explicitly stated below**, are authored by and remain under the copyright of the original project author - Pop-a-ball (https://github.com/Pop-a-ball).

---

## Third-Party Open Source Components

### WinDivert

**Project:** WinDivert - Windows packet diversion library  
**Author:** Bas Vermeulen (basil at covus dot com)  
**License:** GPLv2 (GNU General Public License v2)  
**Source:** https://www.reqrypt.org/windivert.html

Used in: `windivert_redirect.exe` for transparent traffic interception and redirection.

**License Text:**

```
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License v2.0 as published
by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License v2.0
along with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
```

For full GPLv2 license text, visit: https://www.gnu.org/licenses/gpl-2.0.html

---

### mitmproxy

**Project:** mitmproxy - Interactive HTTPS proxy  
**Authors:** Aldo Cortesi, Maximilian Hils, and mitmproxy contributors  
**License:** MIT (Massachusetts Institute of Technology License)  
**Source:** https://mitmproxy.org  
**Repository:** https://github.com/mitmproxy/mitmproxy

Used in: HTTP/HTTPS request interception and response injection (optional, development/deployment only).

**License Text:**

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### Internet Archive / Wayback Machine

**Organization:** Internet Archive  
**Website:** https://archive.org  
**Wayback Machine:** https://web.archive.org

Wikipedia snapshot content (CSS, JavaScript, and HTML structure) retrieved from Internet Archive's Wayback Machine.

**Attribution:** This project uses archived Wikipedia content from the Internet Archive. Wikipedia content is available under Creative Commons Attribution-ShareAlike 3.0 (CC-BY-SA 3.0).

**Note:** This project is not affiliated with, endorsed by, or connected to Wikipedia, Wikimedia Foundation, or the Internet Archive.

---

### Rust Standard Library and Dependencies

The `scanner.dll` is built with Rust, which includes various open-source dependencies licensed under MIT and Apache 2.0 licenses. These are automatically compiled and included. All dependencies are:
- MIT License
- Apache License 2.0
- Unlicense
- BSD licenses

---

**Last Updated:** January 29, 2026
