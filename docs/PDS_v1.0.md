# 📜 دستور النظام الرسمي الموحد — PenFlow Domain Specification (PDS v1.0)
## (Autonomous Security Research Platform — Master Constitution & Domain Specification)

---

## 🌌 1. العوالم الأربعة والطبقة الخمسية (The 4 Worlds & The 5th Experience Layer)

ينقسم مجتمع كائنات ونماذج نظام **PenFlow** إلى أربعة عوالم أساسية تُمثل البنية المكانية والمعرفية، بالإضافة إلى **الطبقة الخمسية الفريدة: طبقة الخبرة المكتسبة (Experience Layer)**.

```mermaid
graph TD
    subgraph 📚 Knowledge World (المعرفة العامة)
        Knowledge["Knowledge"]
        Technique["Technique"]
        Playbook["Playbook"]
        Research["Research"]
        Pattern["Pattern"]
    end

    subgraph 🎯 Target World (العالم الحقيقي للهدف)
        Program["Program"]
        Target["Target"]
        Scope["Scope"]
        Asset["Asset"]
        Technology["Technology"]
        Endpoint["Endpoint"]
        Parameter["Parameter"]
        Identity["Identity"]
        Session["Session"]
        Relationship["Relationship"]
    end

    subgraph ⚡ Execution World (بيئة التنفيذ والتخيل)
        Goal["Goal"]
        Plan["Plan"]
        Task["Task"]
        Workflow["Workflow"]
        Execution["Execution"]
        Observation["Observation"]
        Decision["Decision"]
        Event["Event"]
        Memory["Memory"]
    end

    subgraph 🏆 Result World (عالم النتائج والأدلة)
        Candidate["Candidate"]
        Finding["Finding"]
        Evidence["Evidence"]
        Verification["Verification"]
        Confidence["Confidence"]
        Report["Report"]
    end

    subgraph 🧬 Experience Layer (الطبقة الخمسية: الخبرة المكتسبة عبر الزمن)
        ExperiencePattern["Experience Pattern (Cross-Program Statistics & Success Heuristics)"]
    end

    Knowledge World <--> Target World
    Target World --> Execution World
    Execution World --> Result World
    Result World -- "Statistical Learnings & Heuristics" --> Experience Layer
    Experience Layer -- "Guides Prioritization" --> Execution World
```

---

## 🏛️ 2. تفصيل العوالم الخمسة (The 5 Worlds Domain Definitions)

### أولاً: عالم المعرفة العامة (Knowledge World)
*لا يعرف شيئاً عن أي هدف محدد؛ يمثل العلم والأبحاث المستقلة عابرة الأهداف:*
1. **`Knowledge`**: معلومة عامة مستمرة (مثل: طبيعة سلوك GraphQL).
2. **`Technique`**: أسلوب فحص أو تجاوز محدد (مثل: JWT Confusion, UUID Swap).
3. **`Playbook`**: خطة تكتيكية كاملة مجمعة من عدة تقنيات (مثل: GraphQL Security Playbook).
4. **`Research`**: مصدر المعرفة الأساسي (مقال، أوراق علمية، تقارير HackerOne، مدونات).
5. **`Pattern`**: النمط الاستنباطي المكتشف (مثال: المسار `/user/{id}` + JWT = احتمالية BOLA/IDOR).

---

### ثانياً: عالم الهدف المالي الحقيقي (Target World)
*الكائنات الحقيقية الخاصة ببرنامج وهدف محدد:*
1. **`Program`**: برنامج Bug Bounty المعتمد.
2. **`Target`**: الشركة أو الهدف المحدد.
3. **`Scope`**: النطاق والتوجيهات المسموحة.
4. **`Asset`**: الأصل التقني المكتشف (Subdomain, IP, S3 Bucket).
5. **`Technology`**: التقنيات المستخدمة (Next.js, GraphQL, PostgreSQL).
6. **`Endpoint`**: نقطة نهاية API أو رابط الويب.
7. **`Parameter`**: متغيرات الطلبات (Query, Body, Header).
8. **`Identity`**: الهويات المشغلة (User A, User B, Admin, Guest).
9. **`Session`**: حالة التوثيق الفعالة للجلسة (Cookies, Bearer Tokens).
10. **`Relationship`**: الروابط والعلاقات الهيكلية (مثال: `Endpoint X` ينتمي لـ `Subdomain Y` ويستخدم `JWT Z`).

---

### ثالثاً: عالم التنفيذ والأحداث (Execution World)
*المحرك الفعلي للعمل والتخطيط:*
1. **`Goal`**: الهدف الأمني المطلوب تحقيقه (مثال: فحص الصلاحيات على نطاق معين).
2. **`Plan`**: الخطة التكتيكية المنشأة للوصول للهدف.
3. **`Task`**: أصغر وحدة عمل تنفيدية فردية.
4. **`Workflow`**: مجموعة مهام متسلسلة مرتبطة بسير عمل معينة.
5. **`Execution`**: سجل تنفيذ المهمة الحقيقي.
6. **`Observation`**: الملاحظة الخام المجردة من التجربة.
7. **`Decision`**: القرار التكتيكي المصنوع من الأيجنت القيادي.
8. **`Event`**: الحدث الصادر والمبثوث عبر الـ EventBus.
9. **`Memory`**: الذاكرة الحية الخاصة بالهدف الحرفي والمحاولات السابقة.

---

### رابعاً: عالم النتائج والأدلة (Result World)
*النتائج والأدلة الموثقة:*
1. **`Candidate`**: نتيجة مشتبه بها مستنتجة أولياً من أيجنتس الفحص.
2. **`Finding`**: النتيجة المعتمدة التي تجاوزت النقد والتحقق.
3. **`Evidence`**: كبسولة الأدلة والإثباتات (HAR, Screenshots, Raw Traces).
4. **`Verification`**: نتيجة عملية التكذيب وإعادة التجربة.
5. **`Confidence`**: الثقة الحسابية المحسبة في النتيجة.
6. **`Report`**: التقرير الشامل النهائي المخصص للباحث البشري.

---

### خامساً: الطبقة الخمسية — الخبرة المكتسبة (Experience Layer)
*الخبرة الإحصائية التراكمية عبر مئات الأهداف:*
1. **`ExperiencePattern`**: الإحصاءات والتحليلات التراكمية الخاصة بالنظام عبر تاريخه (الفرق بين المعرفة والذاكرة والخبرة):
   * **Knowledge**: "تقارير PortSwigger تقول إن GraphQL قد يكون عرضة لاختبار معين."
   * **Memory**: "على target.com جربنا هذه التقنية يوم 1 أغسطس وكانت النتيجة 403."
   * **Experience**: "خلال آخر 200 برنامج Bug Bounty، عندما اجتمعت الخصائص التالية (GraphQL + JWT + تعدد الأدوار)، نجحت تقنية BOLA بنسبة 78%."

---

## 🔒 3. مصفوفة الصلاحيات والرؤية المحدودة (Scoped Visibility & Ownership Matrix)

### ⚠️ المبدأ الصارم رقم 1: الرؤية المحدودة والتقسيم التخصصي الضيق (Principle of Scoped Visibility)
**لا يُسمح لأي أيجنت بالوصول لجميع البيانات، بل يُمنح كل أيجنت نطاق رؤية محدد وضيق (Scoped Context View) لمنع التشتت ومنح تخصص أعمق.**

| اسم الأيجنت / الفريق | نطاق الرؤية المسموح (Allowed Scoped Context) | الكيانات التي يحق له إنشاؤها (Create) | الأحداث الصادرة |
| :--- | :--- | :--- | :--- |
| **Planner Agent** | `Target State, Technologies, Goals` | `Goal`, `Plan`, `Task` | `PlanCreated`, `TaskCreated` |
| **Recon Team** | `Target, Scope, Assets, DNS` | `Asset`, `Observation` | `AssetDiscovered`, `ObservationCaptured` |
| **IDOR / BOLA Agent** | `Endpoint, Parameter, Identity, Session` | `Candidate` (فقط اشتباه) | `CandidateDiscovered` |
| **Cloud Agent** | `Buckets, IAM, Metadata, DNS` | `Candidate` (خاص بالسحابة) | `CandidateDiscovered` |
| **Business Logic Agent**| `Workflow, Transactions, Prices, States` | `Candidate` (خاص بالمنطق) | `CandidateDiscovered` |
| **Validator / Critic** | `Candidate, Baseline Observations` | `Finding`, `VerifiedFinding`, `Discarded` | `FindingVerified`, `FindingRejected` |
| **Knowledge Agent** | `Research Papers, Public Writeups` | `Knowledge`, `Technique`, `Pattern`, `Playbook` | `KnowledgeUpdated` |
| **Memory Agent** | `Execution Logs, Target State` | `Memory` | `MemoryUpdated` |
| **Report Agent** | `VerifiedFinding, Evidence` (Read-Only) | `Report` | `ReportReady` |

---

## 🔄 4. دورة حياة الكيانات والتحويل المشروط (Entity Transitions)

```
Recon Team (Observation)
         │
         ▼
Security Specialist Agent (Candidate)
         │
         ▼
Critic Validation Agent
  ├────────────────────────────────┐
  ▼                                ▼
[Falsified / Rejected]      [Verified]
  │                                │
  ▼                                ▼
Discarded Candidate        VerifiedFinding (Confidence >= 90%)
                                   │
                                   ▼
                         Evidence Collection (HAR / PoC)
                                   │
                                   ▼
                         Experience Pattern Learned
                                   │
                                   ▼
                         Report Ready for Human
```

---
*تم اعتماد الدستور المحدث PDS v1.0 رسميًا لتأكيد العوالم الـ 5 والرؤية المحدودة للأيجنتات.*
