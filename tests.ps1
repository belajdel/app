# Fetch the CSRF token
$csrfToken = (Invoke-RestMethod -Uri "http://localhost:3000/csrf-token" | Select-Object -ExpandProperty csrfToken)

# Login and get the user token
$userToken = (Invoke-RestMethod -Uri "http://localhost:3000/login" -Method Post -Body (ConvertTo-Json -InputObject @{ username = "john_doe"; password = "password123" }) -Headers @{ "Content-Type" = "application/json"; "X-CSRF-Token" = $csrfToken } | Select-Object -ExpandProperty token)

# Access the protected endpoint
Invoke-RestMethod -Uri "http://localhost:3000/api/video-caption" -Headers @{ "Authorization" = $userToken; "X-CSRF-Token" = $csrfToken }