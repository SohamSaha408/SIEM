import unittest
from datetime import datetime
# Import parsing functions directly from our parser script
from parse_logs import parse_nginx_line, parse_auth_line

class TestLogParsers(unittest.TestCase):
    
    def test_parse_nginx_success_log(self):
        """Test parsing of a standard Nginx 200 GET request."""
        sample_line = '192.168.1.15 - - [14/Jul/2026:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0"'
        result = parse_nginx_line(sample_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '192.168.1.15')
        self.assertEqual(result['method'], 'GET')
        self.assertEqual(result['url'], '/index.html')
        self.assertEqual(result['status'], '200')
        self.assertEqual(result['bytes'], '1043')
        
    def test_parse_nginx_directory_traversal_payload(self):
        """Test parsing of an Nginx log containing directory traversal characters."""
        sample_line = '198.51.100.250 - - [14/Jul/2026:14:14:48 +0000] "GET /static/../../../../etc/passwd HTTP/1.1" 404 227 "-" "Nmap"'
        result = parse_nginx_line(sample_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '198.51.100.250')
        self.assertEqual(result['url'], '/static/../../../../etc/passwd')
        self.assertEqual(result['status'], '404')

    def test_parse_auth_ssh_failed_login(self):
        """Test parsing of an SSH failed login log line."""
        sample_line = 'Jul 14 06:00:00 server sshd[15000]: Failed password for invalid user root from 203.0.113.200 port 61234 ssh2'
        result = parse_auth_line(sample_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['source_ip'], '203.0.113.200')
        self.assertEqual(result['action'], 'Failed Login')
        self.assertEqual(result['target_user'], 'root')
        
    def test_parse_auth_ssh_accepted_login(self):
        """Test parsing of an SSH accepted login log line."""
        sample_line = 'Jul 14 00:03:00 server sshd[22203]: Accepted password for bob from 192.168.1.105 port 55601 ssh2'
        result = parse_auth_line(sample_line)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['source_ip'], '192.168.1.105')
        self.assertEqual(result['action'], 'Successful Login')
        self.assertEqual(result['target_user'], 'bob')

    def test_parse_auth_pam_session_open(self):
        """Test parsing of a local PAM session opening (missing external IP)."""
        sample_line = 'Jul 14 00:03:01 server sshd[22203]: pam_unix(sshd:session): session opened for user bob by (uid=0)'
        result = parse_auth_line(sample_line)
        
        self.assertIsNotNone(result)
        self.assertIsNone(result['source_ip']) # Raw log has no IP, parser should yield None which is later filled as 127.0.0.1 by pandas
        self.assertEqual(result['action'], 'Session Opened')
        self.assertEqual(result['target_user'], 'bob')

if __name__ == '__main__':
    unittest.main()
