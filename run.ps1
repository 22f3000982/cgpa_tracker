# CGPA Tracker - IIT Madras BS Program
# =====================================

Write-Host "CGPA Tracker - IIT Madras BS Program" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

Write-Host ""
Write-Host "Starting the application..." -ForegroundColor Green
Write-Host "Open your browser and go to: http://localhost:5000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

python app.py

Read-Host "Press Enter to exit"
