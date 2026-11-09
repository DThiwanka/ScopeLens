/**
 * Tests for Phase 6: Sensitive Data Leakage & Privacy Analyzer
 */

import { assertEqual, assertTrue } from './test-utils.js';
import { LeakageAnalyzer } from '../src/modules/leakage/leakage-analyzer.js';

export function runLeakageAnalyzerTests() {
  const analyzer = new LeakageAnalyzer();

  // Test 1: Stack trace detection
  const stackContent = `Error: DB Connection Failed
    at Database.connect (C:\\Users\\admin\\app\\db.js:42:15)
    at async startServer (/var/www/node/server.js:10:5)`;
  
  const stackFindings = analyzer.scanContent({
    content: stackContent,
    url: 'https://example.com/api/debug'
  });

  assertTrue(stackFindings.some(f => f.id === 'LEAKAGE_STACK_TRACE'), 'Detected server stack trace');
  assertTrue(stackFindings.some(f => f.id === 'LEAKAGE_INTERNAL_PATH'), 'Detected internal system paths');

  // Test 2: Internal IP detection
  const ipContent = `// Gateway configured to proxy to internal backend 10.150.4.22 and redis at 192.168.1.50`;
  const ipFindings = analyzer.scanContent({
    content: ipContent,
    url: 'https://example.com/assets/config.js'
  });
  assertTrue(ipFindings.some(f => f.id === 'LEAKAGE_INTERNAL_IP'), 'Detected private RFC 1918 IPs in comments');

  // Test 3: Form auditing (Password in GET and Mixed Form Submission)
  const forms = [
    { action: 'https://example.com/login', method: 'GET', hasPassword: true },
    { action: 'http://insecure-api.com/submit', method: 'POST', hasPassword: false }
  ];
  const formFindings = analyzer.auditForms(forms, 'https://example.com/login');
  assertTrue(formFindings.some(f => f.id === 'FORM_PASSWORD_IN_GET'), 'Detected password in GET form');
  assertTrue(formFindings.some(f => f.id === 'FORM_MIXED_SUBMISSION'), 'Detected mixed form submission');

  // Test 4: Header version disclosure
  const headers = {
    'Server': 'Apache/2.4.41 (Ubuntu)',
    'X-Powered-By': 'PHP/7.4.3'
  };
  const headerFindings = analyzer.auditHeaders(headers);
  assertEqual(headerFindings.length, 2, 'Found 2 version disclosure headers');
  assertTrue(headerFindings.some(f => f.id === 'HEADER_VERSION_LEAK_SERVER'), 'Detected server version leak');
}
