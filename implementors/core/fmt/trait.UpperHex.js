(function() {var implementors = {};
implementors["delog"] = [{"text":"impl&lt;'a, T:&nbsp;?Sized, U, S&gt; UpperHex for HexStr&lt;'a, T, U, S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: AsRef&lt;[u8]&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;U: Unsigned,<br>&nbsp;&nbsp;&nbsp;&nbsp;S: Separator,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["generic_array"] = [{"text":"impl&lt;T:&nbsp;ArrayLength&lt;u8&gt;&gt; UpperHex for GenericArray&lt;u8, T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Add&lt;T&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;T as Add&lt;T&gt;&gt;::Output: ArrayLength&lt;u8&gt;,&nbsp;</span>","synthetic":false,"types":[]}];
implementors["half"] = [{"text":"impl UpperHex for bf16","synthetic":false,"types":[]},{"text":"impl UpperHex for f16","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()