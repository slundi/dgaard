# List formats

| **Format**           | **Use Case**                     | **Example**            |
| :------------------- | :------------------------------- | :--------------------- |
| **Original (hosts)** | Pi-hole, hosts file              | `0.0.0.0 example.com`  |
| **No IP (domains)**  | Some routers, simple lists       | `example.com`          |
| **DNSMASQ**          | dnsmasq DNS server               | `server=/example.com/` |
| **AdGuard**          | AdGuard Home, browser extensions | `\|\|example.com^`     |

## dnsmasq lines

dgaard reads dnsmasq rules the way dnsmasq applies them, and keeps only the
ones that block:

| Line                                                          | Meaning in dnsmasq             | Loaded as |
| :------------------------------------------------------------ | :----------------------------- | :-------- |
| `server=/ads.com/`, `local=/ads.com/`                         | answer locally only → NXDOMAIN | block     |
| `address=/ads.com/`                                           | NXDOMAIN                       | block     |
| `address=/ads.com/0.0.0.0` (or `::`, `127.0.0.1`, `::1`, `#`) | sinkhole                       | block     |
| `server=/corp.example/10.0.0.53`                              | forward to that server         | ignored   |
| `server=/corp.example/#`                                      | use the default servers        | ignored   |
| `address=/printer.lan/192.168.1.20`                           | redirect to a real host        | ignored   |

A blocking rule covers the domain **and all its subdomains** (like
`||ads.com^`), and one line may list several domains
(`address=/a.com/b.com/0.0.0.0`). Each domain is validated; `#` as a domain
("every name") is refused.
