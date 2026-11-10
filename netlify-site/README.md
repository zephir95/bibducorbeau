# Mes films : GitHub + Netlify

Le code vit sur **GitHub**, **Netlify** le met en ligne et le met à jour tout seul à chaque changement. La petite fonction `netlify/functions/api.mjs` gère les comptes, les profils et le catalogue (stockage Netlify Blobs, aucun autre service à créer).

## 1. Mettre le code sur GitHub
1. Dézippez `netlify-site.zip`.
2. Sur github.com : **+ > New repository**, nom `mes-films`, **Private**, **Create repository**.
3. **uploading an existing file**, glissez tout le contenu du dossier (y compris le dossier `netlify`), puis **Commit changes**.

## 2. Relier Netlify à GitHub
1. Sur netlify.com, connectez-vous **avec GitHub**.
2. **Add new site > Import an existing project > GitHub >** votre dépôt `mes-films`. Laissez les réglages par défaut, **Deploy**.
3. **Site configuration > Environment variables > Add a variable** : `ADMIN_CODE` = votre code admin (long de préférence).
4. **Deploys > Trigger deploy > Deploy site** pour que la variable soit prise en compte.

Ensuite, chaque fichier modifié sur GitHub redéploie le site automatiquement. Vos données (catalogue, comptes, profils) ne sont pas dans GitHub : elles restent dans Netlify Blobs et survivent aux redéploiements.

## 3. Ce que peut faire chacun
- **Visiteurs** : lire la collection et les profils publics, chercher, ouvrir des fiches, voir recommandations et nouveautés.
- **Profils** (pseudo + mot de passe) : modifier leur propre profil, enregistré automatiquement ≈ 3 s après chaque changement ; top 5 de leurs films préférés ; profil public ou privé.
- **Admin** (bouton 🔒 Admin + `ADMIN_CODE`) : la collection, les réglages et la **gestion des profils** (Réglages > Gestion des profils).

## 4. Gestion des profils (admin)
- **Inscriptions** : ouvertes, sur validation (vous cliquez sur « Valider ✅ »), ou fermées ; **plafond** de profils.
- **Mots de passe** : chiffrés de façon irréversible (scrypt + sel). Personne, vous compris, ne peut les lire.
- **Code de secours à 10 chiffres** par profil : il remplace le mot de passe pour se connecter. Vous le voyez dans la liste (👁), pour le redonner à quelqu'un qui a perdu son mot de passe. « Accéder 🔑 » ouvre le profil avec ce code, « Nouveau code 🔄 » en génère un autre, « Supprimer 🗑️ » efface le profil.
- Après récupération, la personne se connecte avec le code puis choisit un nouveau mot de passe (Réglages > Mon compte).
- 5 mauvais essais verrouillent un compte 15 minutes.

## 5. Nouveautés en streaming et recommandations
Elles utilisent TMDB : Réglages > **Clé TMDB** (clé gratuite sur themoviedb.org > Paramètres > API). Sur Netlify, TMDB fonctionne directement.

## Bon à savoir
- Le code de secours est lisible par quiconque connaît `ADMIN_CODE` : gardez-le secret et choisissez un code long.
- Pas de « mot de passe oublié » automatique : c'est l'admin qui redonne le code de secours.
- Sans la fonction, le site fonctionne en lecture avec `catalog.json`, et les profils restent locaux à l'appareil.
