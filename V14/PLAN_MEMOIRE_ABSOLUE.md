# Plan — Mémoire absolue de Cassandra

Objectif : une mémoire **fiable à 3000%**, **illimitée en stockage** mais **bornée dans le
prompt**, qui **ne ment plus** (vérifie ou dit « je ne sais pas »), articulée autour de
**BookStack comme source de vérité de référence**.

Décisions validées :
- Embeddings : **locaux (sentence-transformers)** — souverains, illimités, hors-ligne.
- Anti-hallucination : **strict** — pas d'affirmation sans source ou vérification, citations obligatoires.
- BookStack : **vérité de référence** — l'agent y lit et y écrit ses apprentissages durables ; en cas de conflit, BookStack prime.

---

## 1. Pourquoi l'agent ment aujourd'hui (causes racines)

1. **La mémoire ne se remplit quasi pas** : l'extraction de faits fait `json.loads()` sur la sortie brute de DeepSeek → casse au moindre texte parasite (même bug que l'évolution Phase1). L'agent n'a donc presque rien de fiable.
2. **Récupération par mots-clés** (FTS5) : rate le fait pertinent s'il est formulé autrement → l'agent ne « voit » pas l'info → il invente.
3. **Aucune distinction vérifié / supposé** : tout est affirmé avec la même assurance.
4. **Consolidation destructrice** : `DELETE` de mémoires selon un LLM peu fiable → perte de données + contradictions.
5. **Pas de provenance ni de citation** : impossible de distinguer le vrai du halluciné.

---

## 2. Architecture cible : mémoire augmentée, sémantique, vérifiable

**Principe fondateur :** stockage illimité, prompt borné. On stocke tout, on n'injecte que
le strict pertinent par recherche sémantique, sous un budget de tokens fixe.

### 2.1 Quatre couches
- **L0 — Identité** (toujours injectée, ~15 lignes max) : agent, serveur, stack, préférences critiques, « vérités absolues » épinglées. Curé et minuscule.
- **L1 — Faits sémantiques** : table `memories` vectorisée. Récupération top-K par similarité de sens.
- **L2 — Encyclopédie BookStack** (source de référence) : pages vectorisées, récupérées **et citées**. L'agent y écrit ses apprentissages durables.
- **L3 — Épisodique** : conversations/actions résumées, consultables à la demande via outil (pas injectées par défaut).

### 2.2 Récupérateur unifié (lecture)
Question → embedding → recherche top-K dans L1 **et** L2 → fusion + classement par
pertinence → assemblage sous **budget tokens fixe (~1500)** → injection. L0 toujours en tête.
Jamais de surcharge, quel que soit le volume stocké.

### 2.3 Pipeline d'écriture (fiable)
Réponse → extraction de faits (**parsing JSON robuste**) → validation (schéma, longueur) →
embedding → **dédup sémantique** → upsert. Les apprentissages durables et de qualité sont
**aussi poussés dans BookStack** (source de référence).
- **Zéro suppression dure** : soft-delete (`status = active | archived | superseded`).
- **Contradiction** : le nouveau fait marque l'ancien `superseded` (versionné dans `memory_history`), au lieu d'empiler des contradictions.

### 2.4 Discipline anti-mensonge (stricte)
- Chaque fait injecté porte **source + date + confiance**.
- Bloc système « RÈGLES DE VÉRITÉ » :
  > Tu n'affirmes un fait QUE s'il provient de ta mémoire / BookStack, ou si tu l'as vérifié par une commande. Sinon : « je ne sais pas » ou tu vérifies. Inventer est interdit. Cite tes sources (mémoire #id, page BookStack).
- **Vérifier plutôt que deviner** : pour tout fait sur le serveur, préférer une commande (bash) à un souvenir incertain.
- **Citations** obligatoires sur les affirmations factuelles → traçabilité, ancrage dans le réel.

---

## 3. Conception technique

### 3.1 Embeddings (local)
- Lib : `sentence-transformers` (PyTorch).
- Modèle multilingue recommandé : `intfloat/multilingual-e5-base` (FR/EN excellents) ou
  `paraphrase-multilingual-MiniLM-L12-v2` (plus léger). Choix final selon RAM dispo.
- Chargé une fois en mémoire (singleton). Calcul des vecteurs à l'écriture ; requête vectorisée à la lecture.

### 3.2 Stockage des vecteurs
- Ajout à `memories` : `embedding BLOB`, `status TEXT DEFAULT 'active'`, `source TEXT`,
  `verified INTEGER DEFAULT 0`, `pinned INTEGER DEFAULT 0`, `last_seen TEXT`.
- Nouvelle table `bookstack_index` : `page_id, title, url, chunk, embedding, updated_at`
  (pages BookStack découpées en chunks + vectorisées, ré-indexées périodiquement).
- Similarité : cosinus en NumPy (brute-force suffisant jusqu'à ~100k entrées). Option future : `sqlite-vec`/FAISS si le volume explose.

### 3.3 Composants à écrire/réécrire
- `embed(text) -> vector` (singleton modèle).
- `memory_search(query, k)` : top-K sémantique sur `memories` (status active) + dédup.
- `bookstack_semantic_search(query, k)` : top-K sur `bookstack_index`.
- `build_memory_context(query, token_budget)` : récupérateur unifié L0+L1+L2 borné.
- `save_memory()` : + embedding + dédup sémantique + soft-delete/supersede + push BookStack si durable.
- `_run_memory_consolidation()` : réécrite — **soft-delete uniquement**, dédup sémantique, jamais de DELETE, prompt nettoyé.
- `extract_learnings_async()` : parsing JSON robuste + validation + scope utilisateur correct.
- Bloc système « RÈGLES DE VÉRITÉ » injecté dans le prompt.
- Indexeur BookStack (au démarrage + périodique).

### 3.4 Impact dépendances / ressources
- `sentence-transformers` + `torch` (~1-2 Go disque, ~0,5-1 Go RAM à l'usage). Serveur ARM64 : roues PyTorch ARM disponibles. À valider : RAM libre du serveur.
- Première indexation (mémoires + BookStack) : quelques secondes à minutes selon volume.

---

## 4. Feuille de route (par phases)

**Phase 1 — Fondations sûres (rapide, ~80 % du ressenti « il ment »)**
- Parsing JSON robuste (extraction + consolidation) → la mémoire se remplit enfin.
- Soft-delete partout (zéro perte) + nettoyage du prompt de consolidation corrompu.
- Bloc « RÈGLES DE VÉRITÉ » + provenance + citations.
- Scope utilisateur corrigé.
→ Livrable : l'agent arrête d'inventer et recommence à mémoriser, sans rien perdre.

**Phase 2 — Moteur sémantique local**
- Intégration sentence-transformers + colonnes vecteurs + `memory_search`.
- Récupérateur unifié borné (remplace l'injection mots-clés).
→ Livrable : « mémoire absolue qui ne surcharge pas le prompt ».

**Phase 3 — BookStack vérité de référence**
- Indexation vectorielle de BookStack + intégration au récupérateur unifié + citations.
- Écriture des apprentissages durables vers BookStack ; BookStack prime en cas de conflit.
→ Livrable : encyclopédie pleinement reliée à la chaîne mémoire.

**Phase 4 — Cohérence & contrôle**
- Supersede automatique des contradictions + UI Mémoire (voir/éditer/épingler « vérité absolue »/purger l'archivé).
→ Livrable : mémoire auto-cohérente et pilotable.

---

## 5. Garde-fous
- Tout passe par le **banc d'essai** d'évolution si appliqué via auto-évolution.
- Sauvegarde de `cassandra_memory.db` avant migration de schéma.
- Dégradation gracieuse : si le modèle d'embeddings est indisponible, repli sur la recherche actuelle (FTS5) — jamais de blocage.
- Rien n'est jamais supprimé physiquement (soft-delete) → réversible.
