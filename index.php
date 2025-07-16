<?php

function fetchHtml($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_HEADER, false);
    $html = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode >= 400 || !$html) {
        return false; // Site returned error or empty
    }

    return $html;
}

function checkVirusTotal($url) {
    $apiKey = 'd64421f2deedcf032fad981a995c4b76f7f9b1b5216c4e98da1ade46cf6d9755'; // Replace with your actual API key
    $vt_url = "https://www.virustotal.com/api/v3/urls";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $vt_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "url=$url");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "x-apikey: $apiKey",
        "Content-Type: application/x-www-form-urlencoded"
    ]);
    $response = curl_exec($ch);
    curl_close($ch);

    $data = json_decode($response, true);
    if (!isset($data['data']['id'])) {
        return null;
    }

    $scan_id = $data['data']['id'];
    $report_url = "https://www.virustotal.com/api/v3/analyses/$scan_id";
    sleep(5); // Wait for scan to complete

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $report_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "x-apikey: $apiKey"
    ]);
    $report = curl_exec($ch);
    curl_close($ch);

    return json_decode($report, true);
}

function scanPhishing($html, $url, &$score) {
    $alerts = [];

    if (preg_match('/\.(ru|cn|tk|ml|ga|cf)$/i', parse_url($url, PHP_URL_HOST))) {
        $alerts[] = "Suspicious domain extension";
        $score += 2;
    }

    $patterns = [
        '/https?:\/\/\d{1,3}(\.\d{1,3}){3}/' => "IP address in content",
        '/paypal.*(login|verify)/i' => "Potential brand spoofing (PayPal)",
        '/<form[^>]*action=["\']http/i' => "Form posting to external domain",
        '/eval\(.*document\.write/i' => "Obfuscated JavaScript",
        '/unescape\(.*?\)/i' => "Potential obfuscation",
        '/base64_decode\(.*?\)/i' => "Base64 encoded content found",
        '/<script[^>]*>.*?window\.location\.href/i' => "Suspicious redirect script",
        '/<iframe[^>]*src=["\']http/i' => "External iframe source"
    ];

    foreach ($patterns as $pattern => $reason) {
        if (preg_match($pattern, $html)) {
            $alerts[] = $reason;
            $score += 2;
        }
    }

    return $alerts;
}

if (isset($_POST['url'])) {
    $url = trim($_POST['url']);
    $html = fetchHtml($url);

    if ($html === false) {
        $results = ["❌ Site returned HTTP error (e.g. 404/500) — unable to scan."];
        $score = 10;
        $riskLevel = "🔴 High Risk - Site may be broken or unsafe.";
    } else {
        $score = 0;
        $results = scanPhishing($html, $url, $score);
        $vt_report = checkVirusTotal($url);

        if ($vt_report && isset($vt_report['data']['attributes']['stats']['malicious'])) {
            $malicious = $vt_report['data']['attributes']['stats']['malicious'];
            if ($malicious > 0) {
                $results[] = "⚠️ Detected as malicious by VirusTotal ($malicious vendors)";
                $score += 6;
            }
        }

        if ($score <= 3) {
            $riskLevel = "✅ Low Risk - Page looks safe.";
        } elseif ($score <= 6) {
            $riskLevel = "⚠️ Medium Risk - Page looks suspicious.";
        } else {
            $riskLevel = "🔴 High Risk - Page likely phishing!";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Phishing Page Detector</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
       body {
        background-color: #87ceeb; /* sky blue */
        padding-top: 40px;
    }
        .container {
            max-width: 700px;
        }
       footer {
    margin-top: 5px;
    padding: 20px 0;
    background: #81CCEA;
    color: #0D0E0D;
}
    </style>
</head>
<body>
    <div class="container bg-white p-4 shadow rounded">
        <h2 class="text-center mb-4">🔍 Phishing Page Detector <!--(PHP + VirusTotal)--></h2>

        <form method="POST" class="mb-4">
            <div class="input-group">
                <input type="text" name="url" class="form-control" placeholder="Enter a URL" required />
                <button type="submit" class="btn btn-primary">Scan</button>
            </div>
        </form>

        <?php if (isset($results)): ?>
            <div class="mb-3">
                <h5>Scan Results for:</h5>
                <p><strong><?= htmlspecialchars($url) ?></strong></p>
                <div class="alert <?= $score <= 3 ? 'alert-success' : ($score <= 6 ? 'alert-warning' : 'alert-danger') ?>">
                    <?= $riskLevel ?>
                </div>
                <ul class="list-group">
                    <?php foreach ($results as $alert): ?>
                        <li class="list-group-item list-group-item-danger">⚠️ <?= $alert ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>
     <div class="container  p-4 shadow rounded mt-4 text-center">
    <footer>
        <p class="mb-0 text-muted">Created by <strong>Forti Peak Limited</strong> (<em>Christian Ohwofasa</em>)</p>
    </footer>
</div>
</body>
</html>
