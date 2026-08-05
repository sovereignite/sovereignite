# Build

All 7 services are defined in `.ko.yaml` and built with `ko`. Container images are
`linux/amd64` with `CGO_ENABLED=1` on a Fedora 44 base.

```bash
ko build --local ./cmd/keymanager
```
