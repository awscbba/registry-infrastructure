#!/usr/bin/env python3
"""
Create a debug bookmarklet to capture authentication state before redirect.
"""

def create_debug_bookmarklet():
    """Create a JavaScript bookmarklet to debug authentication state"""
    
    print("🔍 Authentication Debug Bookmarklet Generator")
    print("=" * 60)
    
    # JavaScript code to capture authentication state
    debug_js = """
(function() {
    console.log('=== AUTH DEBUG START ===');
    
    // Check localStorage
    console.log('localStorage contents:');
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);
        console.log(`  ${key}: ${value}`);
    }
    
    // Check for specific auth keys
    const authToken = localStorage.getItem('authToken');
    const userAuthToken = localStorage.getItem('userAuthToken');
    const userData = localStorage.getItem('userData');
    const userEmail = localStorage.getItem('userEmail');
    
    console.log('Auth-specific keys:');
    console.log(`  authToken (old): ${authToken ? 'present' : 'missing'}`);
    console.log(`  userAuthToken (new): ${userAuthToken ? 'present' : 'missing'}`);
    console.log(`  userData: ${userData ? 'present' : 'missing'}`);
    console.log(`  userEmail: ${userEmail ? 'present' : 'missing'}`);
    
    // Check current page
    console.log(`Current URL: ${window.location.href}`);
    console.log(`Page title: ${document.title}`);
    
    // Check for any auth-related elements
    const loginForm = document.querySelector('form');
    const emailInput = document.querySelector('input[type="email"]');
    const passwordInput = document.querySelector('input[type="password"]');
    
    console.log('Page elements:');
    console.log(`  Login form: ${loginForm ? 'present' : 'missing'}`);
    console.log(`  Email input: ${emailInput ? 'present' : 'missing'}`);
    console.log(`  Password input: ${passwordInput ? 'present' : 'missing'}`);
    
    // Try to prevent redirect temporarily
    const originalReplace = window.location.replace;
    const originalAssign = window.location.assign;
    
    window.location.replace = function(url) {
        console.log(`🚨 REDIRECT BLOCKED: location.replace('${url}')`);
        console.log('This redirect was temporarily blocked for debugging');
        return false;
    };
    
    window.location.assign = function(url) {
        console.log(`🚨 REDIRECT BLOCKED: location.assign('${url}')`);
        console.log('This redirect was temporarily blocked for debugging');
        return false;
    };
    
    // Also intercept href changes
    const originalHref = window.location.href;
    Object.defineProperty(window.location, 'href', {
        set: function(url) {
            console.log(`🚨 REDIRECT BLOCKED: location.href = '${url}'`);
            console.log('This redirect was temporarily blocked for debugging');
        },
        get: function() {
            return originalHref;
        }
    });
    
    console.log('🛡️ Redirects temporarily blocked for 10 seconds');
    console.log('Check the console output above for authentication state');
    
    // Restore redirects after 10 seconds
    setTimeout(() => {
        window.location.replace = originalReplace;
        window.location.assign = originalAssign;
        console.log('🔓 Redirects restored');
    }, 10000);
    
    console.log('=== AUTH DEBUG END ===');
    
    // Show alert with key info
    const summary = `
AUTH DEBUG SUMMARY:
- authToken (old): ${authToken ? 'PRESENT' : 'MISSING'}
- userAuthToken (new): ${userAuthToken ? 'PRESENT' : 'MISSING'}
- Current page: ${window.location.pathname}
- Redirects blocked for 10 seconds
Check console for full details!
    `;
    
    alert(summary);
})();
    """.strip()
    
    # Create bookmarklet URL
    bookmarklet = f"javascript:{debug_js}"
    
    print("📋 INSTRUCTIONS:")
    print("1. Copy the bookmarklet code below")
    print("2. Create a new bookmark in your browser")
    print("3. Paste the code as the URL")
    print("4. Name it 'Auth Debug'")
    print("5. After login attempt, immediately click the bookmark")
    print("")
    
    print("🔖 BOOKMARKLET CODE:")
    print("=" * 60)
    print(bookmarklet)
    print("=" * 60)
    
    # Also create a simpler version for manual console execution
    simple_debug = """
console.log('=== QUICK AUTH DEBUG ===');
console.log('authToken (old):', localStorage.getItem('authToken') ? 'present' : 'missing');
console.log('userAuthToken (new):', localStorage.getItem('userAuthToken') ? 'present' : 'missing');
console.log('userData:', localStorage.getItem('userData') ? 'present' : 'missing');
console.log('Current URL:', window.location.href);
console.log('=== END DEBUG ===');
    """.strip()
    
    print("\n📝 ALTERNATIVE: Manual Console Code")
    print("If bookmarklet doesn't work, paste this in browser console:")
    print("=" * 60)
    print(simple_debug)
    print("=" * 60)
    
    print("\n🎯 WHAT TO DO:")
    print("1. Open browser developer tools (F12)")
    print("2. Go to Console tab")
    print("3. Attempt login with srinclan+test001@gmail.com")
    print("4. IMMEDIATELY after clicking login, click the bookmark")
    print("5. Check console output for authentication state")
    print("6. The redirect will be blocked for 10 seconds")
    
    print("\n🔍 WHAT WE'RE LOOKING FOR:")
    print("✅ If fix is deployed:")
    print("   - userAuthToken should be present")
    print("   - authToken should be missing")
    print("   - Should stay on dashboard page")
    print("")
    print("❌ If fix is NOT deployed:")
    print("   - authToken might be present (old code)")
    print("   - userAuthToken might be missing")
    print("   - Redirect happens because dashboard can't find token")
    
    return {
        "bookmarklet": bookmarklet,
        "simple_debug": simple_debug
    }

if __name__ == "__main__":
    result = create_debug_bookmarklet()
    print(f"\n✅ Debug tools created successfully")
    print(f"🚀 Ready to capture authentication state during login")
