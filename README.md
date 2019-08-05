# Log Analyzer

Intelligent log file analysis with pattern detection, anomaly alerts, and insights.

## Features

- Multi-format support (Apache, Nginx, Laravel, JSON, syslog)
- Error pattern detection
- Anomaly detection (sudden spikes, unusual patterns)
- Statistical analysis
- Timeline visualization
- Real-time monitoring
- Alert rules
- Export reports

## Usage

```php
// Analyze log file
$analyzer = new LogAnalyzer('/var/log/app.log');
$results = $analyzer->analyze();

// Get errors
$errors = $analyzer->errors()->count(); // 42

// Detect patterns
$patterns = $analyzer->patterns(); // Most common error types

// Timeline analysis
$timeline = $analyzer->timeline('1 hour'); // Events per hour

// Anomaly detection
$anomalies = $analyzer->anomalies(); // Unusual activity
```

## CLI

```bash
# Analyze log
php artisan log:analyze /var/log/nginx/access.log

# Monitor in real-time
php artisan log:monitor /var/log/app.log --tail

# Generate report
php artisan log:report /var/log/*.log --output=report.html
```

## Detections

- HTTP error spikes (4xx, 5xx)
- Slow query patterns
- Failed authentication attempts
- Memory/resource issues
- Unusual traffic patterns

## Requirements

- PHP 7.2+
