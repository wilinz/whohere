# oui 分支

IEEE OUI 登记表的紧凑快照 `oui.txt.gz`，解开是
`<6位十六进制前缀><TAB><厂商名>` 一行一条，
由 `main` 分支上的 `.github/workflows/oui.yml` 每 3 天自动刷新。

- 构建期：`tools/fetch-oui.sh` 从这里取，解压后打进 ipk。
- 路由器上：`update-oui.sh` / LuCI 的「更新 OUI 库」按钮也从这里取，拉的就是这份 gz。

直链：`https://raw.githubusercontent.com/wilinz/whohere/oui/oui.txt.gz`
