#!/usr/bin/env python3
"""
Create a log interceptor to capture console logs before redirect.
"""

def create_log_interceptor():
    """Create JavaScript code to intercept and persist console logs"""
    
    print("🔍 Console Log Interceptor Generator")
    print("=" * 60)
    
    # JavaScript code to intercept console logs and store them
    interceptor_js = """
// Log Interceptor - Paste this in console BEFORE login
(function() {
    console.log('🔧 Log interceptor installed');
    
    // Array to store all logs
    window.capturedLogs = [];
    
    // Store original console methods
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    
    // Intercept console.log
    console.log = function(...args) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            type: 'log',
            timestamp: timestamp,
            args: args,
            message: args.join(' ')
        };
        window.capturedLogs.push(logEntry);
        
        // Also store in localStorage for persistence
        try {
            localStorage.setItem('capturedLogs', JSON.stringify(window.capturedLogs));
        } catch(e) {}
        
        // Call original console.log
        originalLog.apply(console, ['[CAPTURED]', timestamp, ...args]);
    };
    
    // Intercept console.error
    console.error = function(...args) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            type: 'error',
            timestamp: timestamp,
            args: args,
            message: args.join(' ')
        };
        window.capturedLogs.push(logEntry);
        
        try {
            localStorage.setItem('capturedLogs', JSON.stringify(window.capturedLogs));
        } catch(e) {}
        
        originalError.apply(console, ['[CAPTURED ERROR]', timestamp, ...args]);
    };
    
    // Intercept console.warn
    console.warn = function(...args) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            type: 'warn',
            timestamp: timestamp,
            args: args,
            message: args.join(' ')
        };
        window.capturedLogs.push(logEntry);
        
        try {
            localStorage.setItem('capturedLogs', JSON.stringify(window.capturedLogs));
        } catch(e) {}
        
        originalWarn.apply(console, ['[CAPTURED WARN]', timestamp, ...args]);
    };
    
    // Also intercept window.location changes
    const originalReplace = window.location.replace;
    const originalAssign = window.location.assign;
    
    window.location.replace = function(url) {
        console.log('🚨 REDIRECT DETECTED: location.replace(' + url + ')');
        console.log('📋 Captured logs before redirect:', window.capturedLogs.length);
        
        // Give a moment for logs to be stored
        setTimeout(() => {
            originalReplace.call(window.location, url);
        }, 100);
    };
    
    window.location.assign = function(url) {
        console.log('🚨 REDIRECT DETECTED: location.assign(' + url + ')');
        console.log('📋 Captured logs before redirect:', window.capturedLogs.length);
        
        setTimeout(() => {
            originalAssign.call(window.location, url);
        }, 100);
    };
    
    // Intercept href changes
    let originalHref = window.location.href;
    Object.defineProperty(window.location, 'href', {
        set: function(url) {
            console.log('🚨 REDIRECT DETECTED: location.href = ' + url);
            console.log('📋 Captured logs before redirect:', window.capturedLogs.length);
            
            setTimeout(() => {
                window.location.replace(url);
            }, 100);
        },
        get: function() {
            return originalHref;
        }
    });
    
    console.log('✅ Log interceptor ready - all console logs will be captured');
    console.log('📝 Access logs with: window.capturedLogs');
    console.log('💾 Logs are also saved to localStorage');
})();
    """.strip()
    
    # JavaScript to retrieve captured logs
    retrieval_js = """
// Log Retrieval - Paste this AFTER redirect to see captured logs
(function() {
    console.log('🔍 Retrieving captured logs...');
    
    // Try to get from current window first
    let logs = window.capturedLogs || [];
    
    // If not found, try localStorage
    if (logs.length === 0) {
        try {
            const storedLogs = localStorage.getItem('capturedLogs');
            if (storedLogs) {
                logs = JSON.parse(storedLogs);
            }
        } catch(e) {
            console.error('Failed to retrieve logs from localStorage:', e);
        }
    }
    
    console.log('📊 Total captured logs:', logs.length);
    
    if (logs.length > 0) {
        console.log('📋 CAPTURED LOGS:');
        console.log('================');
        
        logs.forEach((log, index) => {
            const prefix = log.type === 'error' ? '❌' : log.type === 'warn' ? '⚠️' : 'ℹ️';
            console.log(`${prefix} [${log.timestamp}] ${log.message}`);
        });
        
        // Filter for Dashboard Debug messages
        const dashboardLogs = logs.filter(log => 
            log.message.includes('[Dashboard Debug]') || 
            log.message.includes('Dashboard Debug')
        );
        
        if (dashboardLogs.length > 0) {
            console.log('\\n🎯 DASHBOARD DEBUG LOGS:');
            console.log('========================');
            dashboardLogs.forEach(log => {
                console.log(`🔍 ${log.message}`);
            });
        }
        
        // Look for authentication-related logs
        const authLogs = logs.filter(log => 
            log.message.includes('auth') || 
            log.message.includes('token') || 
            log.message.includes('login')
        );
        
        if (authLogs.length > 0) {
            console.log('\\n🔐 AUTHENTICATION LOGS:');
            console.log('=======================');
            authLogs.forEach(log => {
                console.log(`🔑 ${log.message}`);
            });
        }
        
        // Clear captured logs
        localStorage.removeItem('capturedLogs');
        console.log('\\n🧹 Captured logs cleared');
    } else {
        console.log('❌ No captured logs found');
    }
})();
    """.strip()
    
    print("📋 STEP-BY-STEP INSTRUCTIONS:")
    print("=" * 60)
    print("1. Open browser developer tools (F12)")
    print("2. Go to Console tab")
    print("3. Paste the LOG INTERCEPTOR code below")
    print("4. Press Enter to install the interceptor")
    print("5. Attempt login with srinclan+test001@gmail.com")
    print("6. After redirect, paste the LOG RETRIEVAL code")
    print("7. Press Enter to see all captured logs")
    print("")
    
    print("🔧 STEP 3: LOG INTERCEPTOR CODE")
    print("=" * 60)
    print(interceptor_js)
    print("=" * 60)
    print("")
    
    print("🔍 STEP 6: LOG RETRIEVAL CODE")
    print("=" * 60)
    print(retrieval_js)
    print("=" * 60)
    
    print("\n🎯 WHAT THIS WILL SHOW:")
    print("- All console.log messages before redirect")
    print("- [Dashboard Debug] messages from our fix")
    print("- Authentication flow details")
    print("- Token validation responses")
    print("- Exact point where redirect happens")
    
    return {
        "interceptor": interceptor_js,
        "retrieval": retrieval_js
    }

if __name__ == "__main__":
    result = create_log_interceptor()
    print(f"\n✅ Log interceptor created successfully")
    print(f"🚀 Ready to capture authentication flow logs")
