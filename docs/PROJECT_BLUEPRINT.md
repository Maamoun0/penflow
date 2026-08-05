# 🏛️ المخطط الهندسي والمعماري المرجعي النهائي لـ منصة PenFlow للأبحاث الأمنية المستقلة
## (PenFlow Autonomous Multi-Agent Security Research Swarm Blueprint)

---

## 1. الرؤية المعمارية المنقحة (System Vision)

تتحول منصة **PenFlow** من مجرد أداة فحص إلى **منصة أبحاث أمنية مستقلة (Autonomous Security Research Platform)** تحاكي فريقاًكاملاً من الباحثين الأمنيين الخبراء. يعتمد كل عضو في هذا الفريق على دور محدد ومسؤولية واضحة، ويتعاونون جميعاً عبر **ناقل أحداث مركزي (Event Bus)** و**ذاكرة مشتركة موحدة (Shared Memory)**.

---

## 2. المخطط المعماري لفريق الأيجنتات (Multi-Agent Swarm Graph)

```mermaid
graph TD
    subgraph 🧠 Strategic & Leadership Swarm
        Director["Research Director Agent (Senior Strategy Lead)"]
        MemoryAgent["Memory Agent (Long-Term Persistence Engine)"]
        KnowledgeAgent["Knowledge Agent (Continuous Intelligence Mining)"]
        CriticAgent["Critic Agent (Adversarial Falsification Engine)"]
        EconomyAgent["Economy Agent (Model & Resource Router)"]
    end

    subgraph ⚡ Recon & Infrastructure Swarm
        ReconAgent["Recon Agent"]
        WebAgent["Web Agent"]
        APIAgent["API Agent"]
        AuthAgent["Authentication Agent"]
        AuthzAgent["Authorization Agent"]
    end

    subgraph 🛡️ Vulnerability Specialists Swarm
        IDORAgent["IDOR / BOLA Agent"]
        BFLAAgent["BFLA Agent"]
        MassAssignAgent["Mass Assignment Agent"]
        LogicAgent["Business Logic Agent"]
    end

    subgraph 📦 Validation & Evidence Swarm
        ValidationAgent["Validation Agent"]
        EvidenceAgent["Evidence Collector Agent"]
        ReportAgent["Report Preparation Agent"]
    end

    subgraph 🚌 Central Communication Core
        EventBus["Event Bus (Publish / Subscribe Pipeline)"]
        SharedMemory["Quad-Memory Shared Engine"]
    end

    Director & MemoryAgent & KnowledgeAgent & CriticAgent & EconomyAgent <--> EventBus
    ReconAgent & WebAgent & APIAgent & AuthAgent & AuthzAgent <--> EventBus
    IDORAgent & BFLAAgent & MassAssignAgent & LogicAgent <--> EventBus
    ValidationAgent & EvidenceAgent & ReportAgent <--> EventBus
    EventBus <--> SharedMemory
```

---

## 3. التغييرات المعمارية الـ 8 الرائدة (8 Architectural Pillars)

1. **فريق الأيجنتات بدلاً من الأيجنت المفرد:** كل باحث رقمي مستقل يركز على اختصاص محدد ويتواصل بالرسائل.
2. **Research Director Agent:** اتخاذ القرارات التكتيكية العالية (هل نواصل الاستكشاف؟ هل التطبيق يستعمل GraphQL؟ هل نحتاج إعادة التخطيط؟).
3. **Memory Agent:** أرشفة وحفظ كل المعطيات لضمان استكمال الأبحاث فور العودة دون بدء من الصفر.
4. **Knowledge Agent:** امتصاص تقارير HackerOne و Bugcrowd العامة والمدونات البحثية واستخراج قواعد جديدة.
5. **Critic Agent:** محاولة نقد وإسقاط أي نتيجة مكتشفة؛ إذا فشل الناقد في إسقاطها، تكتسب دقة وثقة شبه مطلقة.
6. **Economy Agent:** التوجيه الذكي للمهام بين النماذج المحلية والذاتية والـ LLMs السحابية لتقليل تكلفة التشغيل وحفظ السرعة.
7. **الذاكرة المشتركة:** التبادل الفوري للمعلومات بين كافة الأيجنتس عبر الـ Event Bus.
8. **التطور التدريجي:** التطوير المتسلسل القائم على إتقان البنية أولاً ثم إضافة الأيجنتس تدريجياً.

---

## 4. البنية البرمجية والمجلدات (Directory Structure)

```
c:\Users\Maamoun\Downloads\antygravity\bug bounty\
├── docs/
│   └── PROJECT_BLUEPRINT.md          # الملف المرجعي المحدث للمشروع
├── penflow/
│   ├── agents/                       # مجلد الأيجنتس المتخصصة
│   │   ├── base_agent.py             # الكلاس الأساسي للأيجنتس والـ Swarm
│   │   ├── director_agent.py         # 🧠 Research Director Agent
│   │   ├── critic_agent.py           # 🔍 Critic Agent
│   │   ├── economy_agent.py          # 💰 Economy Agent
│   │   ├── memory_agent.py           # 💾 Memory Agent
│   │   ├── knowledge_agent.py        # 📚 Knowledge Agent
│   │   ├── idor_agent/               # 🛡️ IDOR / BOLA Agent
│   │   ├── bfla_agent/               # 🛡️ BFLA Agent
│   │   ├── mass_assign_agent/        # 🛡️ Mass Assignment Agent
│   │   └── logic_agent/              # 🛡️ Business Logic Agent
│   ├── core/                         # الناقل الموحد Event Bus
│   ├── memory/                       # محرك الذاكرة الرباعية
│   ├── observation/                  # كائن الأحداث والملاحظات
│   ├── evidence/                     # تجميع الأدلة والـ HAR
│   └── reporting/                    # إعداد التقارير للباحث البشري
├── tests/                            # الاختبارات التلقائية الشاملة
└── run.py                            # مشغل المنصة المستقلة
```

---
*تم اعتماد الهيكلية المعمارية الجديدة بتميز من فريق الذكاء الاصطناعي والتطوير.*
