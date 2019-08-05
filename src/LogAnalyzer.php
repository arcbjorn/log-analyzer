<?php

namespace Arcbjorn\LogAnalyzer;

class LogAnalyzer
{
    protected $logFile;
    protected $lines = [];
    protected $parsed = [];

    public function __construct($logFile)
    {
        $this->logFile = $logFile;
        $this->load();
    }

    protected function load()
    {
        if (!file_exists($this->logFile)) {
            throw new \Exception("Log file not found: {$this->logFile}");
        }

        $this->lines = file($this->logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->parse();
    }

    protected function parse()
    {
        foreach ($this->lines as $line) {
            $entry = $this->parseLine($line);
            if ($entry) {
                $this->parsed[] = $entry;
            }
        }
    }

    protected function parseLine($line)
    {
        // Parse common log formats (Apache, Nginx, Laravel)

        // Apache/Nginx combined format
        if (preg_match('/^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+)/', $line, $matches)) {
            return [
                'ip' => $matches[1],
                'timestamp' => $matches[2],
                'request' => $matches[3],
                'status' => (int) $matches[4],
                'size' => (int) $matches[5],
                'type' => 'access',
                'level' => $this->getLogLevel($matches[4])
            ];
        }

        // Laravel log format
        if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \w+\.(\w+): (.*)/', $line, $matches)) {
            return [
                'timestamp' => $matches[1],
                'level' => strtoupper($matches[2]),
                'message' => $matches[3],
                'type' => 'application'
            ];
        }

        // Generic error log
        if (preg_match('/(ERROR|WARNING|INFO|DEBUG)/i', $line, $matches)) {
            return [
                'level' => strtoupper($matches[1]),
                'message' => $line,
                'type' => 'generic'
            ];
        }

        return null;
    }

    protected function getLogLevel($statusCode)
    {
        if ($statusCode >= 500) return 'ERROR';
        if ($statusCode >= 400) return 'WARNING';
        return 'INFO';
    }

    public function analyze()
    {
        return [
            'total_entries' => count($this->parsed),
            'errors' => $this->errors()->count(),
            'warnings' => $this->warnings()->count(),
            'status_codes' => $this->getStatusCodeDistribution(),
            'top_ips' => $this->getTopIPs(),
            'timeline' => $this->timeline('1 hour')
        ];
    }

    public function errors()
    {
        $errors = array_filter($this->parsed, function ($entry) {
            return $entry['level'] === 'ERROR';
        });

        return new LogResult($errors);
    }

    public function warnings()
    {
        $warnings = array_filter($this->parsed, function ($entry) {
            return $entry['level'] === 'WARNING';
        });

        return new LogResult($warnings);
    }

    protected function getStatusCodeDistribution()
    {
        $distribution = [];

        foreach ($this->parsed as $entry) {
            if (isset($entry['status'])) {
                $code = $entry['status'];
                $distribution[$code] = ($distribution[$code] ?? 0) + 1;
            }
        }

        arsort($distribution);
        return $distribution;
    }

    protected function getTopIPs($limit = 10)
    {
        $ips = [];

        foreach ($this->parsed as $entry) {
            if (isset($entry['ip'])) {
                $ip = $entry['ip'];
                $ips[$ip] = ($ips[$ip] ?? 0) + 1;
            }
        }

        arsort($ips);
        return array_slice($ips, 0, $limit, true);
    }

    public function timeline($interval = '1 hour')
    {
        $timeline = [];

        foreach ($this->parsed as $entry) {
            if (!isset($entry['timestamp'])) continue;

            $timestamp = strtotime($entry['timestamp']);
            $bucket = floor($timestamp / 3600) * 3600; // Hour buckets

            $timeline[$bucket] = ($timeline[$bucket] ?? 0) + 1;
        }

        ksort($timeline);
        return $timeline;
    }

    public function patterns()
    {
        $patterns = [];

        foreach ($this->parsed as $entry) {
            if (!isset($entry['message'])) continue;

            // Extract error patterns
            if (preg_match('/\b(timeout|connection|failed|exception|error)\b/i', $entry['message'], $matches)) {
                $pattern = strtolower($matches[1]);
                $patterns[$pattern] = ($patterns[$pattern] ?? 0) + 1;
            }
        }

        arsort($patterns);
        return $patterns;
    }

    public function anomalies()
    {
        $anomalies = [];

        // Detect sudden spikes in errors
        $timeline = $this->timeline('1 hour');
        $values = array_values($timeline);
        $avg = count($values) > 0 ? array_sum($values) / count($values) : 0;

        foreach ($timeline as $time => $count) {
            if ($count > $avg * 3) { // 3x average
                $anomalies[] = [
                    'time' => date('Y-m-d H:i:s', $time),
                    'count' => $count,
                    'reason' => 'Spike detected (3x average)'
                ];
            }
        }

        return $anomalies;
    }
}

class LogResult
{
    protected $entries;

    public function __construct(array $entries)
    {
        $this->entries = array_values($entries);
    }

    public function count()
    {
        return count($this->entries);
    }

    public function get()
    {
        return $this->entries;
    }
}
