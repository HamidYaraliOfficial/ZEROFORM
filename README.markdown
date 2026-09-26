<div align="center">

# ZEROFORM
### Security Reality Compiler

**Turn a declarative model of your system into an executable, testable, simulate-able security architecture.**

[English](#english) · [فارسی](#فارسی) · [中文](#中文)

</div>

---

<a name="english"></a>
## English

### 1. What is ZEROFORM?

ZEROFORM compiles a **Reality Model** — a declarative description of your users, services, devices, APIs,
databases, queues, secrets, trust zones, AI agents and the flows between them — into a canonical graph,
then analyzes it, synthesizes machine-readable security controls, generates signed policy artifacts,
and lets you simulate, break, refactor and re-verify the architecture entirely offline, before any of it
touches production.

It ships as a Python library + CLI, a REST/WebSocket API (FastAPI), and a standalone Windows‑11‑styled
web dashboard (plain HTML/CSS/JS, no build step).

> **Scope note.** This repository is a complete, runnable **reference implementation** of the ZEROFORM
> architecture: the DSL, compiler pipeline, graph engine, trust-boundary/control-synthesis/policy engines,
> the capability-sandboxed policy runtime, scenario simulation, mutation testing, version control, audit
> trail, and the GUI all work end-to-end against the bundled sample world out of the box. A handful of
> pieces are deliberately built as clean **extension points** rather than turnkey integrations — a live
> Neo4j-backed graph store, a compiled `.wasm` guest module, an SMT/SAT-backed formal verifier, and a
> production KMS/HSM signer — because those require external infrastructure the reference build should
> not assume you have. Each is documented in the code where it plugs in.

### 2. Key capabilities

- **ZEROFORM Reality DSL** — a small, typed, block-based language (`world`, `trust_zone`, `identity`,
  `service`, `api`, `database`, `secret`, `agent`, `flow`, `policy`, `scenario`, …) with lists, nested
  blocks and `import` statements.
- **Canonical Reality Graph** — a storage-agnostic graph model (`GraphRepository`) with a ready-to-use
  in-memory NetworkX backend and a documented Neo4j adapter surface.
- **Compiler pipeline** — `Lex/Parse → AST → Semantic Model → Graph Build → Security Analysis → Control
  Synthesis → Policy Compilation → Simulation Model → Verification → Artifact Generation`, with every
  stage's output inspectable and a determinism guarantee (same input ⇒ same artifact hashes).
- **Classification, Trust Zone & Trust Boundary engines** — propagate data classification across flows
  and turn every trust-zone crossing into a concrete set of required controls (authentication,
  authorization, encryption, input validation, output filtering, rate limiting, audit, data
  minimization, approval, isolation, segmentation, secrets management, integrity verification, session
  controls, backup verification, data-loss prevention).
- **Identity & Privilege Propagation engine** — walks role/delegation chains to surface excessive
  privilege, privilege chains, orphan permissions and dangerous delegations.
- **Security Gap Analyzer & Path Analyzer** — direct database access, shared secrets, missing
  classification, critical/sensitive/external/cross-boundary paths, and a Data Exposure Simulator for
  "what if this control were removed" questions.
- **Policy Generator + capability-sandboxed Policy Runtime** — compiles controls into signed JSON /
  OPA-compatible / HTTP-middleware / gRPC-interceptor / event-validator policy documents and evaluates
  them through the exact `authorize / validate_data / check_boundary / evaluate_context /
  require_control / audit_decision / verify_integrity` interface a compiled `.wasm` guest would expose,
  with every decision carrying a reason, rule id, evidence, required control and obligations.
- **Virtual Security Environment** — a Scenario Designer + Execution Engine covering the built-in
  scenario templates (stolen credential, compromised device, leaked secret, misconfigured API,
  unauthorized data export, service failure, identity escalation, third-party trust change, policy
  removal, encryption failure, audit failure, AI-agent over-permission), a Security State Machine, and a
  Counterfactual Lab for branching/comparing "what if" architectures.
- **Refactoring engine** — proposes concrete, versioned graph transformations (insert a gateway, extract
  a secret store, add an approval layer, …) with security benefit, functional impact and operational
  cost, plus an Architecture Equivalence Analyzer to separate security improvements from functional
  regressions.
- **Verification & Mutation Testing** — an Invariant Engine, a Verification Scenario Generator (positive
  / negative / boundary / context / failure / recovery cases), a Property-Based Security Tester, and a
  Security Mutation Testing Framework that measures whether your test suite would actually catch a
  weakened policy.
- **Reality Version Control** — a small git-like object store (commit / branch / tag / diff / restore)
  with a Security Branching System (baseline / experimental / hardened / future / audit-candidate).
- **Audit Engine** — an append-only, hash-chained record of every change, so tampering is detectable.
- **Secure Package Format & Secret Boundary Engine** — exports schema + policies + scenarios + artifacts
  as a zip that can never contain a raw secret value, only references.
- **Compliance Mapping, Documentation Compiler & Release Passport** — maps controls to configurable
  framework references (never claims compliance on its own) and generates architecture / trust-boundary
  / control-matrix / verification-matrix Markdown docs plus a per-version summary artifact.
- **Operating Hours / Virtual SOC availability panel** — the user enters the support desk's weekly hours
  (or 24/7, or per-date holiday exceptions) and ZEROFORM works out whether it is open right now and the
  exact time remaining until the next opening or closing — nothing is hard-coded.
- **GUI** — a Windows‑11/Fluent‑styled dashboard with five themes (Windows default, Light, Dark, Red,
  Blue) and three languages (English, Persian/RTL, Chinese), talking to the REST API or, offline, to a
  bundled demo compile.

### 3. Project layout

```
zeroform/
├── zeroform/
│   ├── dsl/                 lexer, parser, AST
│   ├── core/                every engine (graph, classification, trust zone, identity,
│   │                        control synthesis, policy generator/runtime, gap & path analysis,
│   │                        virtual environment, refactor, verification, mutation testing,
│   │                        audit, version control, availability, compliance, documentation,
│   │                        artifact registry, importers, AI assistant, pipeline)
│   ├── api/                 FastAPI REST + WebSocket service
│   ├── examples/             sample_world.zf
│   └── cli.py                `zeroform` command line interface
├── gui/                      standalone HTML/CSS/JS dashboard
├── deploy/helm/zeroform/     Kubernetes Helm chart
├── tests/                    pytest regression suite
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── pyproject.toml
```

### 4. Installation

Requires **Python 3.10+**.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
# or, for an editable install that also gives you the `zeroform` command:
pip install -e .
```

### 5. Quick start (CLI)

```bash
# scaffold a new Reality Model (or use the bundled sample directly)
zeroform init --sample world.zf

# inspect it
zeroform model world.zf

# run the full compiler pipeline
zeroform compile world.zf --explain

# gap analysis only
zeroform analyze world.zf

# generate signed policy artifacts
zeroform policy world.zf --out policies/

# run invariants + property-based consistency checks
zeroform verify world.zf

# propose architecture refactors for the current findings
zeroform refactor world.zf

# mutation-test the compiled policy
zeroform test world.zf

# diff two models
zeroform diff world_a.zf world_b.zf

# build a Secure Package (no raw secret values, ever)
zeroform package world.zf --out package.zip

# build the Security Release Passport + Markdown documentation
zeroform report world.zf --out passport.json

# current SOC / support desk status and countdown to the next change
zeroform hours
```

### 6. Running the API + GUI

```bash
zeroform run --host 127.0.0.1 --port 8000
# then open gui/index.html in a browser (or serve it: `python3 -m http.server 8080` inside gui/)
# and set the API base URL in Settings if it isn't the default http://127.0.0.1:8000
```

### 7. Docker / Kubernetes

```bash
docker compose up --build         # API on :8000, GUI on :8080

# Kubernetes (Helm):
helm install zeroform deploy/helm/zeroform \
  --set image.repository=your-registry/zeroform \
  --set image.tag=0.1.0
# create the signing-key secret referenced by values.yaml first:
kubectl create secret generic zeroform-signing-key --from-literal=signing-key="$(openssl rand -hex 32)"
```

### 8. Tests

```bash
pytest -q
```

### 9. License

Apache License 2.0 — see [`LICENSE`](./LICENSE).

---

<a name="فارسی"></a>
<div dir="rtl">

## فارسی

### ۱. زیروفرم چیست؟

زیروفرم یک **مدل واقعیت** (Reality Model) — یعنی توصیفی اعلانی از کاربران، سرویس‌ها، دستگاه‌ها، APIها،
پایگاه‌های داده، صف‌ها، رازها (Secrets)، ناحیه‌های اعتماد (Trust Zone)، عامل‌های هوش مصنوعی و جریان‌های
میان آن‌ها — را به یک گراف استاندارد کامپایل می‌کند، آن را تحلیل می‌کند، کنترل‌های امنیتی
ماشین‌خوان تولید می‌کند، آرتیفکت‌های پالیسی امضاشده می‌سازد و به شما اجازه می‌دهد کاملاً به‌صورت آفلاین،
پیش از رسیدن به محیط Production، معماری را شبیه‌سازی، خراب، بازطراحی و دوباره تأیید کنید.

این پروژه به‌صورت یک کتابخانهٔ پایتون + خط فرمان، یک API با REST/WebSocket (بر پایهٔ FastAPI)، و یک
داشبورد وب مستقل با ظاهر ویندوز ۱۱ (HTML/CSS/JS ساده، بدون نیاز به build) ارائه می‌شود.

> **دربارهٔ محدودهٔ پروژه.** این مخزن یک **پیاده‌سازی مرجع** کامل و قابل‌اجرا از معماری زیروفرم است: DSL،
> خط لولهٔ کامپایلر، موتور گراف، موتورهای مرز اعتماد/سنتز کنترل/پالیسی، ران‌تایم پالیسی با ساندباکس
> مبتنی بر Capability، شبیه‌سازی سناریو، تست جهش (Mutation Testing)، کنترل نسخه، ثبت رخداد (Audit) و
> رابط کاربری، همگی به‌صورت سر تا سر و در برابر جهان نمونهٔ همراه پروژه کار می‌کنند. چند بخش عمداً به‌صورت
> **نقطهٔ توسعهٔ** تمیز طراحی شده‌اند نه یکپارچه‌سازی آماده — یک پایگاه گراف زندهٔ Neo4j، یک ماژول
> کامپایل‌شدهٔ `.wasm`، یک تأییدکنندهٔ صوری مبتنی بر SMT/SAT، و یک امضاکنندهٔ KMS/HSM در محیط Production —
> چون این‌ها به زیرساخت خارجی نیاز دارند که نسخهٔ مرجع نباید فرض کند شما آن را دارید. محل اتصال هرکدام در
> کد مستندسازی شده است.

### ۲. قابلیت‌های اصلی

- **DSL واقعیت زیروفرم** — زبانی کوچک، Typed و بلوک‌محور (`world`، `trust_zone`، `identity`، `service`،
  `api`، `database`، `secret`، `agent`، `flow`، `policy`، `scenario` و…) با پشتیبانی از لیست، بلوک‌های
  تودرتو و دستور `import`.
- **گراف واقعیت استاندارد (Canonical Reality Graph)** — مدل گرافی مستقل از فناوری ذخیره‌سازی
  (`GraphRepository`) با یک Backend آماده مبتنی بر NetworkX در حافظه و یک لایهٔ Adapter مستندشده برای
  Neo4j.
- **خط لولهٔ کامپایلر** — مراحل `Lex/Parse → AST → Semantic Model → Graph Build → Security Analysis →
  Control Synthesis → Policy Compilation → Simulation Model → Verification → Artifact Generation`، با
  خروجی قابل‌بازرسی در هر مرحله و تضمین قطعیت (Determinism): ورودی یکسان همیشه هش آرتیفکت یکسان تولید
  می‌کند.
- **موتورهای طبقه‌بندی، ناحیهٔ اعتماد و مرز اعتماد** — طبقه‌بندی داده را در طول جریان‌ها منتشر می‌کنند و
  هر عبور از مرز اعتماد را به مجموعه‌ای مشخص از کنترل‌های لازم تبدیل می‌کنند (احراز هویت، تفویض اختیار،
  رمزنگاری، اعتبارسنجی ورودی، فیلتر خروجی، محدودسازی نرخ، ثبت رخداد، حداقل‌سازی داده، تأیید انسانی،
  ایزوله‌سازی، بخش‌بندی، مدیریت رازها، تأیید یکپارچگی، کنترل نشست، تأیید پشتیبان‌گیری، جلوگیری از نشت
  داده).
- **موتور هویت و انتشار امتیاز** — زنجیره‌های نقش/تفویض را دنبال می‌کند تا امتیاز مازاد، زنجیرهٔ امتیاز،
  مجوز یتیم و تفویض خطرناک را نمایان کند.
- **تحلیل‌گر شکاف امنیتی و تحلیل‌گر مسیر** — دسترسی مستقیم به پایگاه‌داده، راز مشترک، طبقه‌بندی‌نشده
  بودن، مسیرهای حیاتی/حساس/خارجی/عبوری از مرز، و یک شبیه‌ساز افشای داده برای پرسش «اگر این کنترل حذف شود
  چه می‌شود؟».
- **تولیدکنندهٔ پالیسی + ران‌تایم پالیسی با ساندباکس Capability-Based** — کنترل‌ها را به اسناد پالیسی
  امضاشدهٔ JSON / سازگار با OPA / Middleware‌ HTTP / Interceptor گونه‌ی gRPC / اعتبارسنج رویداد کامپایل
  می‌کند و آن‌ها را دقیقاً از طریق همان رابط `authorize / validate_data / check_boundary /
  evaluate_context / require_control / audit_decision / verify_integrity` که یک ماژول کامپایل‌شدهٔ
  `.wasm` ارائه می‌دهد ارزیابی می‌کند؛ هر تصمیم شامل دلیل، شناسهٔ قاعده، شواهد، کنترل لازم و تعهدات است.
- **محیط امنیتی مجازی** — طراح سناریو + موتور اجرا برای الگوهای آماده (سرقت اعتبارنامه، دستگاه
  آلوده‌شده، راز افشاشده، API با پیکربندی نادرست، خروج غیرمجاز داده، خرابی سرویس، تشدید هویت، تغییر
  اعتماد به شخص ثالث، حذف پالیسی، خرابی رمزنگاری، خرابی ممیزی، امتیاز مازاد عامل هوش مصنوعی)، یک ماشین
  حالت امنیتی و یک آزمایشگاه ضدواقعیت برای شاخه‌سازی و مقایسهٔ سناریوهای «اگر...».
- **موتور بازطراحی** — تبدیل‌های گراف مشخص و نسخه‌بندی‌شده پیشنهاد می‌دهد (افزودن Gateway، استخراج
  Secret Store، افزودن لایهٔ تأیید و…) همراه با فایده‌ی امنیتی، اثر عملکردی و هزینهٔ عملیاتی، به‌همراه
  تحلیل‌گر هم‌ارزی معماری برای جدا کردن بهبود امنیتی از پسرفت عملکردی.
- **تأیید و تست جهش** — موتور Invariant، تولیدکنندهٔ سناریوی تأیید (حالت‌های مثبت/منفی/مرزی/زمینه‌ای/
  خرابی/بازیابی)، آزمونگر امنیتی مبتنی بر ویژگی و چارچوب تست جهش امنیتی که مشخص می‌کند آیا مجموعه تست
  شما واقعاً یک پالیسی تضعیف‌شده را کشف می‌کند یا نه.
- **کنترل نسخهٔ واقعیت** — یک مخزن شیء کوچک شبیه Git (commit / branch / tag / diff / restore) با سیستم
  شاخه‌بندی امنیتی (baseline / experimental / hardened / future / audit-candidate).
- **موتور ممیزی (Audit)** — ثبت append-only و زنجیرشده با هش از هر تغییر، به‌طوری‌که دستکاری قابل کشف
  باشد.
- **فرمت بستهٔ امن و موتور مرز راز** — schema، پالیسی‌ها، سناریوها و آرتیفکت‌ها را در قالب یک zip صادر
  می‌کند که هرگز نمی‌تواند مقدار واقعی یک راز را در خود داشته باشد، فقط ارجاع.
- **نگاشت انطباق، کامپایلر مستندسازی و پاسپورت انتشار** — کنترل‌ها را به مرجع‌های قابل‌تنظیم چارچوب‌های
  انطباق نگاشت می‌کند (هرگز خودش ادعای انطباق نمی‌کند) و مستندات Markdown معماری/مرز اعتماد/ماتریس
  کنترل/ماتریس تأیید به‌همراه یک آرتیفکت خلاصهٔ هر نسخه تولید می‌کند.
- **پنل ساعات کاری / دسترس‌پذیری مرکز عملیات امنیتی مجازی** — کاربر ساعات هفتگی میز پشتیبانی را وارد
  می‌کند (یا ۲۴ ساعته، یا استثناهای تعطیلی برای تاریخ‌های خاص) و زیروفرم خودش مشخص می‌کند که الان باز
  است یا نه و دقیقاً چقدر تا باز یا بسته شدن بعدی مانده — هیچ‌چیز از پیش تعیین‌شده نیست.
- **رابط کاربری** — داشبوردی با ظاهر ویندوز ۱۱/Fluent با پنج پوسته (پیش‌فرض ویندوز، روشن، تاریک، قرمز،
  آبی) و سه زبان (انگلیسی، فارسی/راست‌چین، چینی)، که با API واقعی یا، در حالت آفلاین، با یک نمونهٔ
  داخلی کار می‌کند.

### ۳. ساختار پروژه

```
zeroform/
├── zeroform/
│   ├── dsl/                 لکسر، پارسر، AST
│   ├── core/                همهٔ موتورها (گراف، طبقه‌بندی، ناحیهٔ اعتماد، هویت،
│   │                        سنتز کنترل، تولیدکننده/ران‌تایم پالیسی، تحلیل شکاف و مسیر،
│   │                        محیط مجازی، بازطراحی، تأیید، تست جهش، ممیزی، کنترل نسخه،
│   │                        ساعات کاری، انطباق، مستندسازی، رجیستری آرتیفکت،
│   │                        وارد‌کننده‌ها، دستیار هوش مصنوعی، خط لولهٔ کامپایلر)
│   ├── api/                 سرویس REST و WebSocket با FastAPI
│   ├── examples/             sample_world.zf
│   └── cli.py                خط فرمان `zeroform`
├── gui/                      داشبورد مستقل HTML/CSS/JS
├── deploy/helm/zeroform/     چارت Helm برای Kubernetes
├── tests/                    مجموعه تست‌های رگرسیون با pytest
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── pyproject.toml
```

### ۴. نصب

نیازمند **Python 3.10 به بالا**.

```bash
python3 -m venv .venv
source .venv/bin/activate        # ویندوز: .venv\Scripts\activate

pip install -r requirements.txt
# یا برای نصب editable که دستور `zeroform` را هم فعال می‌کند:
pip install -e .
```

### ۵. شروع سریع (خط فرمان)

```bash
# ساخت یک مدل واقعیت جدید (یا استفادهٔ مستقیم از نمونهٔ همراه پروژه)
zeroform init --sample world.zf

# بررسی آن
zeroform model world.zf

# اجرای کامل خط لولهٔ کامپایلر
zeroform compile world.zf --explain

# فقط تحلیل شکاف
zeroform analyze world.zf

# تولید آرتیفکت‌های پالیسی امضاشده
zeroform policy world.zf --out policies/

# اجرای بررسی Invariantها و تست‌های سازگاری مبتنی بر ویژگی
zeroform verify world.zf

# پیشنهاد بازطراحی معماری برای یافته‌های فعلی
zeroform refactor world.zf

# تست جهش روی پالیسی کامپایل‌شده
zeroform test world.zf

# مقایسهٔ دو مدل
zeroform diff world_a.zf world_b.zf

# ساخت یک بستهٔ امن (بدون هیچ مقدار خام رازی)
zeroform package world.zf --out package.zip

# ساخت پاسپورت انتشار امنیتی + مستندات Markdown
zeroform report world.zf --out passport.json

# وضعیت فعلی میز پشتیبانی/SOC و شمارش معکوس تا تغییر بعدی
zeroform hours
```

### ۶. اجرای API و رابط کاربری

```bash
zeroform run --host 127.0.0.1 --port 8000
# سپس فایل gui/index.html را در مرورگر باز کنید (یا با `python3 -m http.server 8080` داخل پوشهٔ gui/ سرو کنید)
# و در صورت نیاز آدرس API را در بخش تنظیمات وارد کنید (پیش‌فرض: http://127.0.0.1:8000)
```

### ۷. Docker / Kubernetes

```bash
docker compose up --build         # API روی پورت ۸۰۰۰، رابط کاربری روی پورت ۸۰۸۰

# Kubernetes (با Helm):
helm install zeroform deploy/helm/zeroform \
  --set image.repository=your-registry/zeroform \
  --set image.tag=0.1.0
# پیش از آن، Secret کلید امضا که در values.yaml به آن ارجاع داده شده را بسازید:
kubectl create secret generic zeroform-signing-key --from-literal=signing-key="$(openssl rand -hex 32)"
```

### ۸. تست‌ها

```bash
pytest -q
```

### ۹. مجوز

مجوز Apache نسخهٔ ۲.۰ — فایل [`LICENSE`](./LICENSE) را ببینید.

</div>

---

<a name="中文"></a>
## 中文

### 1. ZEROFORM 是什么？

ZEROFORM 将一份**现实模型（Reality Model）**——即对用户、服务、设备、API、数据库、消息队列、密钥、
信任区域（Trust Zone）、AI 代理及其相互之间数据流的声明式描述——编译为一张标准化图谱，随后对其进行
分析、合成机器可读的安全控制措施、生成已签名的策略产物，并让你在完全离线、不触碰生产环境的情况下，
对整个架构进行模拟、破坏测试、重构与再验证。

项目以 Python 库 + 命令行工具、REST/WebSocket API（基于 FastAPI），以及一个独立的、采用
Windows 11 风格的网页仪表盘（纯 HTML/CSS/JS，无需构建步骤）三种形式提供。

> **范围说明。** 本仓库是 ZEROFORM 架构的一份完整、可运行的**参考实现**：DSL、编译流水线、图引擎、
> 信任边界/控制合成/策略引擎、基于能力沙箱的策略运行时、场景仿真、变异测试、版本控制、审计追踪以及
> 图形界面，针对内置的示例世界均可端到端运行。其中少数部分被有意设计为清晰的**扩展点**而非开箱即用
> 的集成——例如实时的 Neo4j 图存储、编译后的 `.wasm` 客体模块、基于 SMT/SAT 的形式化验证器，以及
> 生产环境的 KMS/HSM 签名器——因为这些都需要参考实现不应默认你已具备的外部基础设施。每一处扩展点均
> 在代码中就近注明。

### 2. 核心能力

- **ZEROFORM Reality DSL** — 一种精简、带类型、以代码块为单位的语言（`world`、`trust_zone`、
  `identity`、`service`、`api`、`database`、`secret`、`agent`、`flow`、`policy`、`scenario` 等），
  支持列表、嵌套代码块以及 `import` 语句。
- **标准现实图谱（Canonical Reality Graph）** — 与存储实现无关的图模型（`GraphRepository`），内置
  基于 NetworkX 的内存后端，并提供已文档化的 Neo4j 适配器接口。
- **编译流水线** — 依次执行 `Lex/Parse → AST → Semantic Model → Graph Build → Security Analysis →
  Control Synthesis → Policy Compilation → Simulation Model → Verification → Artifact Generation`，
  每个阶段的输出均可检查，并保证确定性（相同输入始终产出相同的产物哈希）。
- **分类、信任区域与信任边界引擎** — 沿数据流传播数据分类标签，并将每一次信任边界穿越转化为一组具体
  所需的控制措施（身份认证、授权、加密、输入校验、输出过滤、限流、审计、数据最小化、人工审批、隔离、
  分段、密钥管理、完整性校验、会话控制、备份校验、数据防泄漏）。
- **身份与权限传播引擎** — 遍历角色/委派链，揭示过度授权、权限链、孤儿权限以及危险的权限委派。
- **安全缺口分析器与路径分析器** — 检测直接数据库访问、共享密钥、缺失分类标签、关键/敏感/外部/跨边界
  路径，并提供数据泄露模拟器，用于回答"若移除此控制措施会发生什么"。
- **策略生成器 + 基于能力沙箱的策略运行时** — 将控制措施编译为已签名的 JSON / 兼容 OPA / HTTP 中间件
  / gRPC 拦截器 / 事件校验器等多种目标格式的策略文档，并通过与编译后 `.wasm` 客体模块完全一致的
  `authorize / validate_data / check_boundary / evaluate_context / require_control / audit_decision /
  verify_integrity` 接口对其求值；每一个决策都携带理由、规则 ID、证据引用、所需控制措施与义务项。
- **虚拟安全环境** — 场景设计器 + 执行引擎，内置多种场景模板（凭据被盗、设备被攻陷、密钥泄露、API
  配置错误、未授权数据导出、服务故障、身份提权、第三方信任变更、策略被移除、加密失效、审计失效、
  AI 代理权限过大），配有安全状态机，以及用于分支与比较"假设"架构的反事实实验室。
- **重构引擎** — 针对当前发现项提出具体、可版本化的图变换建议（插入安全网关、拆分出独立密钥存储、
  增加审批层等），并给出安全收益、功能影响与运维成本，配合架构等价性分析器区分"安全改进"与
  "功能回归"。
- **验证与变异测试** — 不变量引擎、验证场景生成器（正向 / 反向 / 边界 / 上下文 / 故障 / 恢复用例）、
  基于属性的安全测试器，以及安全变异测试框架，用于衡量你的测试套件是否真的能发现被削弱的策略。
- **现实版本控制** — 一个类 Git 的轻量对象存储（commit / branch / tag / diff / restore），配合安全
  分支体系（baseline / experimental / hardened / future / audit-candidate）。
- **审计引擎** — 对每一次变更进行仅追加、哈希链式记录，使篡改行为可被检测。
- **安全包格式与密钥边界引擎** — 将模式定义、策略、场景与产物导出为 zip 包，该包永远不会包含任何
  密钥明文，只会包含引用。
- **合规映射、文档编译器与发布护照** — 将控制措施映射到可配置的合规框架引用（本身从不声称已合规），
  并自动生成架构图 / 信任边界图 / 控制矩阵 / 验证矩阵等 Markdown 文档及每个版本的摘要产物。
- **工作时间 / 虚拟安全运营中心可用性面板** — 用户输入支持台的每周工作时间（或 24 小时营业，或按
  具体日期设置假期例外），ZEROFORM 会自动判断当前是否营业，以及距离下一次开放或关闭的确切剩余时间——
  没有任何硬编码内容。
- **图形界面** — 采用 Windows 11 / Fluent 风格的仪表盘，提供五种主题（Windows 默认、浅色、深色、
  红色、蓝色）与三种语言（英语、波斯语/从右到左、中文），可连接真实 REST API，离线时则使用内置示例
  数据进行演示。

### 3. 项目结构

```
zeroform/
├── zeroform/
│   ├── dsl/                 词法分析器、语法分析器、AST
│   ├── core/                全部引擎（图谱、分类、信任区域、身份、
│   │                        控制合成、策略生成器/运行时、缺口与路径分析、
│   │                        虚拟环境、重构、验证、变异测试、审计、版本控制、
│   │                        工作时间、合规、文档编译、产物注册表、
│   │                        导入器、AI 助手、编译流水线）
│   ├── api/                 基于 FastAPI 的 REST + WebSocket 服务
│   ├── examples/             sample_world.zf 示例
│   └── cli.py                `zeroform` 命令行工具
├── gui/                      独立的 HTML/CSS/JS 仪表盘
├── deploy/helm/zeroform/     Kubernetes Helm Chart
├── tests/                    pytest 回归测试套件
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── pyproject.toml
```

### 4. 安装

需要 **Python 3.10 及以上**版本。

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
# 或者使用可编辑安装，同时启用 `zeroform` 命令：
pip install -e .
```

### 5. 快速开始（命令行）

```bash
# 创建一个新的现实模型（或直接使用内置示例）
zeroform init --sample world.zf

# 查看模型概况
zeroform model world.zf

# 运行完整编译流水线
zeroform compile world.zf --explain

# 仅运行缺口分析
zeroform analyze world.zf

# 生成已签名的策略产物
zeroform policy world.zf --out policies/

# 运行不变量检查与基于属性的一致性测试
zeroform verify world.zf

# 针对当前发现项提出架构重构建议
zeroform refactor world.zf

# 对已编译的策略进行变异测试
zeroform test world.zf

# 比较两个模型
zeroform diff world_a.zf world_b.zf

# 构建安全包（绝不包含任何密钥明文）
zeroform package world.zf --out package.zip

# 生成安全发布护照 + Markdown 文档
zeroform report world.zf --out passport.json

# 查看当前 SOC / 支持台状态及距下次状态变化的倒计时
zeroform hours
```

### 6. 运行 API 与图形界面

```bash
zeroform run --host 127.0.0.1 --port 8000
# 然后在浏览器中打开 gui/index.html（或在 gui/ 目录下运行 `python3 -m http.server 8080` 提供服务）
# 如果 API 地址不是默认的 http://127.0.0.1:8000，请在"设置"中修改
```

### 7. Docker / Kubernetes

```bash
docker compose up --build         # API 位于 :8000，图形界面位于 :8080

# Kubernetes（使用 Helm）：
helm install zeroform deploy/helm/zeroform \
  --set image.repository=your-registry/zeroform \
  --set image.tag=0.1.0
# 部署前，先创建 values.yaml 中引用的签名密钥 Secret：
kubectl create secret generic zeroform-signing-key --from-literal=signing-key="$(openssl rand -hex 32)"
```

### 8. 测试

```bash
pytest -q
```

### 9. 许可证

Apache License 2.0 — 详见 [`LICENSE`](./LICENSE) 文件。
