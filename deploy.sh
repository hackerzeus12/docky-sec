#!/bin/bash
echo "CLIENT : getting updates and building"
cd dockysec-client
git pull
npm install
npm run build

echo "CLIENT : applying changes"
pm2 delete client
pm2 serve build 3000 --name client --spa

cd ../

echo "SERVER : getting updates and building"
cd dockysec-server
git pull
npm install

echo "CLIENT : applying changes"
pm2 delete server
pm2 start index.js --name server

cd ../

echo "Deployment Completed"

