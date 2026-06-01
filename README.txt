ECBU Liaison Pro - version serveur professionnelle autonome

1) Sur un PC serveur local :
- installer Python 3.10+
- lancer AUTORISER_PAREFEU_WINDOWS.bat en administrateur
- lancer LANCER_SERVEUR_ECBU.bat
- ouvrir http://127.0.0.1:8000 sur le PC serveur
- créer le seul compte administrateur
- créer les comptes prescripteurs, laboratoire et chef_labo

2) Depuis les autres PC / téléphones du même réseau :
- ouvrir http://ADRESSE-IP-DU-PC-SERVEUR:8000
- aucun Python nécessaire sur ces appareils.

3) Pour accès à des milliers de kilomètres et même PC éteint :
- il faut héberger ce dossier sur un serveur cloud/VPS/hébergeur.
- utiliser Procfile inclus : web: python server.py --host 0.0.0.0 --port $PORT
- définir ECBU_SECRET dans les variables d'environnement.
- sauvegarder ecbu_liaison.db régulièrement ou passer à PostgreSQL pour production.

Rôles :
- admin : crée/suspend les comptes, export technique, ne voit pas les données médicales.
- prescripteur : crée les demandes, voit uniquement ses résultats et archives.
- laboratoire : reçoit les demandes, attribue le N° d’échantillon, contrôle la conformité, saisit les résultats.
- chef_labo : voit tous les bilans, valide avant envoi au clinicien prescripteur.

Bon de résultat :
- une page A4, reprend les rubriques exactes du PDF fourni : laboratoire, hôpital, n° labo, n° d’échantillon, examens macro/micro, gram, culture, antibiogramme EUCAST, conclusion, validation.
