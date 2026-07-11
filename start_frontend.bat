@echo off
cd frontend
if not exist node_modules (
    echo node_modules not found. Running npm install first...
    npm install
)
npm run dev
pause
