package filter

// rustFixtureLists are the rule lists the Rust server 0.41.1 answered from,
// cut down to the rules that can touch a query in rustFixtureVerdicts. Lines
// keep the forms of the original generated lists: ||domain^, ||domain, @@||,
// hosts entries with and without a trailing comment, bare domains, upper case,
// and the lines that are no rule at all (comments, blanks, localhost, junk).
var rustFixtureLists = [3]string{
	`0.0.0.0 sub3.site1864.test
||site545.test^
||site71.io^
site384.example
site827.org
0.0.0.0 site2164.example
||SITE1875.ORG
site1428.org
||site1606.com
||site1411.example^
||site545.test
0.0.0.0 site471.example
@@||site332.example^
||site976.io^
0.0.0.0 SITE2837.NET
127.0.0.1 site1562.test # note
0.0.0.0 site1905.net
sub4.site1404.co.uk
0.0.0.0 site773.org
@@||site1393.net^
||site2613.org^
||site1876.io^
0.0.0.0 site435.org
||site1598.co.uk
||site2794.example^
||site1620.com^
||site621.co.uk^
||site139.org
||site1411.example^
||SITE459.NET^
0.0.0.0 site2362.org
0.0.0.0 site1246.org
||SITE232.EXAMPLE^
||site1336.net
site120.io
||site2015.net^
||site817.net
0.0.0.0 site2473.example
0.0.0.0 site1348.com
@@||site1473.org^
||site2289.co.uk^
0.0.0.0 site1697.com
||site183.net^
site76.test
||site1503.example^
||site1766.example^
site286.com
||site2950.com^
||site2115.org
||site1398.co.uk^
||SITE1684.IO
||sub3.site334.org
||site428.net^
@@||site1604.com^
||site1609.example
@@||site2668.co.uk^
site2750.io
||site831.net^
site2555.org
site1225.example
127.0.0.1 site758.com # note
||site334.org
||site1115.test^
0.0.0.0 sub3.site2974.com
||SITE779.COM^
@@||SITE273.EXAMPLE^
@@||site1642.com^
@@||site820.co.uk^
0.0.0.0 site773.org
@@||SUB1.SITE167.NET^
||sub2.site705.org^
@@||SITE1535.IO^
||site2667.org
0.0.0.0 site590.io
0.0.0.0 site506.co.uk
||site1525.net^
127.0.0.1 sub3.site2016.com # note
||site667.example^
||SUB0.SITE1564.CO.UK^
||site1096.co.uk
site2802.io
site251.org
||site1580.io^
||site1246.org
0.0.0.0 sub3.site156.org
||SITE2529.IO
@@||site1315.io^
0.0.0.0 site871.example
site315.io
0.0.0.0 site1921.org
||site1371.com^
@@||site118.io^
||site1519.example^
0.0.0.0 site456.net
||site1912.net^
||site443.org
0.0.0.0 site1336.net
||site1571.com^
||site1697.com
0.0.0.0 site1947.io
||site1225.example^
||sub3.site332.example^
||site2837.net
0.0.0.0 site2696.org
@@||site1483.com^
site2483.io
@@||site2725.org^
||site524.co.uk^
||site246.io^
@@||site1930.com^
||site2070.org^
@@||site917.co.uk^
||site1822.co.uk
||site1947.io^
||site1851.co.uk^
||SITE853.TEST^
site251.org
||site395.io
||site2240.io^
||site2362.org
0.0.0.0 site1648.org
||site354.example
||site395.io^
site2115.org
site2450.io
site1701.co.uk
||SITE2851.NET^
@@||site2148.test^
||site2015.net^
||sub2.site492.org
||site676.net^
||site2391.org
||site829.co.uk^
0.0.0.0 site2185.co.uk
@@||site612.net^
site2185.co.uk
@@||site2613.org^
0.0.0.0 SITE2831.CO.UK
||site2476.test^
@@||site345.co.uk^
||site2667.org^
127.0.0.1 SITE9.EXAMPLE # note
||SITE77.IO^
0.0.0.0 site993.co.uk
||site315.io^
@@||site2328.io^
0.0.0.0 site1975.com
||site1864.test^
||site613.example^
||site2607.io^
||site590.io^
||site49.co.uk
||site330.net^
@@||site1955.test^
||SITE2363.COM^
site2757.io
@@||sub2.site1398.co.uk^
||site928.io^
||site2522.net^
||site2017.co.uk
||SITE0.IO^
||site1115.test^
||site2578.example^
@@||SITE2680.EXAMPLE^
site191.org
127.0.0.1 SUB0.SITE1533.ORG # note
@@||site782.test^
||site234.org^
site649.com
||site1663.example^
||site2756.co.uk^
||site2348.com
site2964.com
site1804.com
||site234.org^
||site649.com^
||SITE435.ORG^
||site2127.co.uk^
@@||site2582.test^
127.0.0.1 site637.co.uk # note
site1905.net
||site1633.example^
@@||site2637.net^
||site0.io
||site827.org^
||site672.org^
||site2219.co.uk^
0.0.0.0 site2945.net
@@||site2696.org^
||site817.net^
||site1999.org
||site2385.co.uk^
site76.test
||site1513.test^
||site1434.io
127.0.0.1 site419.io # note
||site1187.test
||site1580.io^
0.0.0.0 sub4.site840.com
||site1973.io^
||site1633.example^
127.0.0.1 site2794.example # note
@@||site1434.io^
SITE774.ORG
||site2901.io^
||site1187.test^
||site2174.io^
sub4.site1822.co.uk
||site974.io
site1876.io
0.0.0.0 site1525.net
||site2756.co.uk^
||site2411.test
0.0.0.0 site428.net
@@||site1385.org^
||site1643.test^
SITE2555.ORG
localhost
0.0.0.0
127.0.0.1 localhost
::1 ip6-localhost
bad rule here
||
@@||
! c
# c

  
`,
	`@@||site1336.net^
0.0.0.0 site452.org
||site1535.io^
||SITE1136.CO.UK^
site2750.io
0.0.0.0 site2476.test
||SITE2473.EXAMPLE
0.0.0.0 site1039.co.uk
@@||site1245.io^
site1096.co.uk
||site67.io^
||SUB3.SITE49.CO.UK^
||site2667.org
||site2974.com
127.0.0.1 site2982.org # note
||site558.test^
0.0.0.0 site2411.test
@@||site2685.io^
0.0.0.0 SITE1039.CO.UK
site191.org
||site927.net^
site2214.com
||site1633.example^
||site492.org^
||site2747.test^
||site661.io
||site1947.io^
127.0.0.1 site974.io # note
sub1.site238.org
||site502.co.uk^
||site435.org^
||site1225.example^
||site1701.co.uk
||sub1.site779.com^
0.0.0.0 site777.com
site2219.co.uk
||site777.com^
@@||site2269.org^
||site524.co.uk^
||site637.co.uk^
||site2224.com
0.0.0.0 site2572.co.uk
site1258.co.uk
||site2473.example^
||site1483.com
||site1955.test
||site2901.io^
127.0.0.1 SITE64.IO # note
||site2164.example^
||site234.org^
||site774.org
||site232.example^
||site2070.org^
||site354.example
0.0.0.0 site273.example
@@||site2011.net^
site2148.test
||site1909.org^
||SITE758.COM^
||site2368.co.uk^
||site590.io^
||site952.com^
||site1398.co.uk^
||site2851.net
0.0.0.0 site2883.io
||SITE1183.TEST^
||site1503.example
||site345.co.uk^
127.0.0.1 site1513.test # note
127.0.0.1 site1246.org # note
||site2866.example^
||site2892.io^
0.0.0.0 site2837.net
0.0.0.0 sub4.site23.org
||site613.example^
||site1896.test^
||SITE702.COM
||site2411.test^
@@||site1875.org^
||site1909.org^
@@||site1604.com^
@@||SITE521.IO^
||site661.io^
||site672.org^
127.0.0.1 site452.org # note
0.0.0.0 site2578.example
@@||site1606.com^
||site120.io
site1774.net
||site1315.io^
site853.test
site315.io
||site2945.net^
@@||site2362.org^
||site2483.io
||site2964.com^
||site705.org^
||site118.io^
||site2702.example^
0.0.0.0 site2348.com
||site1371.com
||site1115.test^
@@||site1519.example^
||site506.co.uk^
0.0.0.0 site2896.test
||SITE456.NET^
0.0.0.0 site917.co.uk
@@||site1851.co.uk^
||site2750.io^
@@||site1811.org^
||site1117.co.uk^
||site1930.com
0.0.0.0 site9.example
||site757.example^
site2115.org
0.0.0.0 site9.example
0.0.0.0 site1804.com
||site853.test
||site782.test^
@@||SITE702.COM^
@@||site1562.test^
||site157.co.uk^
||site2901.io^
@@||site2127.co.uk^
||site557.test^
site2450.io
||sub1.site612.net^
||site273.example
@@||site2950.com^
@@||site2385.co.uk^
||site773.org^
site2798.io
||site2522.net^
||site557.test^
||site2220.io^
||site1876.io^
@@||site2802.io^
||site2802.io^
||site2607.io^
||sub3.site71.io^
0.0.0.0 site1348.com
||site2178.example^
||site2363.com^
site1335.co.uk
site395.io
||SITE1924.NET^
@@||site2831.co.uk^
0.0.0.0 site2555.org
||site2725.org^
||site2178.example^
@@||site871.example^
0.0.0.0 site820.co.uk
||sub0.site2791.org^
||site133.net^
@@||site2476.test^
@@||site155.test^
site831.net
||site2045.example^
@@||site89.net^
||site2127.co.uk
||site2550.example^
127.0.0.1 site1349.io # note
0.0.0.0 site2798.io
||site927.net^
||site334.org^
||sub0.site1924.net
0.0.0.0 site2550.example
||site1663.example^
||site2668.co.uk
site2756.co.uk
0.0.0.0 sub0.site443.org
||site1183.test^
||site2532.example
0.0.0.0 site2185.co.uk
0.0.0.0 site1349.io
0.0.0.0 SITE1906.EXAMPLE
||site952.com
0.0.0.0 site2051.co.uk
127.0.0.1 site831.net # note
0.0.0.0 site67.io
||site1807.io^
||site384.example^
0.0.0.0 site1428.org
||site608.com^
||site928.io^
||site384.example
||site1864.test^
127.0.0.1 site2572.co.uk # note
127.0.0.1 site1598.co.uk # note
0.0.0.0 site1735.com
@@||site2725.org^
@@||site64.io^
site774.org
@@||site331.com^
@@||SITE1315.IO^
||site1007.test^
0.0.0.0 site471.example
@@||site928.io^
||site633.test^
||site280.com^
||site1398.co.uk^
||site2555.org^
||site1483.com^
||SITE2668.CO.UK^
||site1620.com
||SITE1525.NET^
localhost
0.0.0.0
127.0.0.1 localhost
::1 ip6-localhost
bad rule here
||
@@||
! c
# c

  
`,
	`0.0.0.0 SITE174.CO.UK
@@||site1980.co.uk^
0.0.0.0 site2348.com
0.0.0.0 SUB4.SITE2851.NET
||site49.co.uk^
||site167.net^
0.0.0.0 site2214.com
@@||site1315.io^
||site111.com^
||site139.org
@@||site1519.example^
||site133.net^
||sub2.site558.test^
||site2757.io^
127.0.0.1 site2070.org # note
||SITE1580.IO
||site2680.example^
||site443.org^
site917.co.uk
0.0.0.0 site1007.test
127.0.0.1 site550.net # note
0.0.0.0 SITE1896.TEST
@@||SITE2671.ORG^
||sub2.site330.net
@@||site2582.test^
||site139.org^
||SITE621.CO.UK
127.0.0.1 site280.com # note
||site2011.net^
@@||site333.org^
||site234.org^
127.0.0.1 site1519.example # note
0.0.0.0 site1906.example
127.0.0.1 sub0.site77.io # note
0.0.0.0 sub4.site521.io
site2362.org
||site419.io
0.0.0.0 site2964.com
||site238.org^
0.0.0.0 sub3.site332.example
||site649.com^
||site976.io^
||site1864.test
||site506.co.uk^
@@||site557.test^
||site2426.org^
||site331.com^
0.0.0.0 site1896.test
||SUB2.SITE2866.EXAMPLE
@@||site2959.test^
||SITE1947.IO^
0.0.0.0 site1096.co.uk
||site2016.com^
@@||site2607.io^
0.0.0.0 sub0.site1571.com
||SITE1909.ORG
||site1912.net^
0.0.0.0 site2385.co.uk
||site243.co.uk^
||site1876.io
||site2756.co.uk^
||site1335.co.uk^
||site156.org^
@@||site2847.example^
||site1999.org^
@@||site1701.co.uk^
||site89.net
||site661.io^
||site2115.org^
||site620.org^
||site1807.io^
0.0.0.0 site1183.test
@@||site1970.org^
||sub1.site1245.io^
||site334.org
@@||site2127.co.uk^
||site2750.io^
0.0.0.0 site2450.io
||site2959.test^
||site1609.example
||site156.org^
@@||site2289.co.uk^
0.0.0.0 site1525.net
||site1663.example
||site315.io^
||site2831.co.uk
||site1973.io^
||site246.io^
||site2883.io^
@@||site1258.co.uk^
||site2982.org^
||site1585.org
||site2411.test^
@@||site2982.org^
site1947.io
||site637.co.uk^
site1535.io
site1901.test
||site2578.example^
||site2363.com^
||sub0.site502.co.uk^
||SITE2945.NET^
||site1930.com^
0.0.0.0 site2683.org
||site2522.net^
||site2391.org^
0.0.0.0 site331.com
||site1067.example^
127.0.0.1 site1697.com # note
0.0.0.0 site1684.io
||site1980.co.uk
||site1901.test^
||site2522.net^
@@||site1643.test^
||site191.org^
||site1790.net
||site2219.co.uk^
site232.example
||SITE280.COM^
site428.net
site2328.io
||site1067.example^
||site976.io
||site1225.example^
||site1136.co.uk^
||site2450.io^
site456.net
site251.org
||site2119.io^
0.0.0.0 site2224.com
||site2269.org
||SITE2070.ORG
0.0.0.0 SUB1.SITE2426.ORG
site286.com
@@||site2667.org^
@@||site2747.test^
@@||site326.test^
site2757.io
||site0.io^
||site219.co.uk
site1535.io
||site1564.co.uk^
site1735.com
0.0.0.0 site1598.co.uk
||site1642.com
0.0.0.0 SITE2115.ORG
||site2532.example^
||site1335.co.uk^
0.0.0.0 site2572.co.uk
||site1117.co.uk
||site506.co.uk^
||site1609.example^
site155.test
site2385.co.uk
site1434.io
0.0.0.0 site2751.test
||site1701.co.uk^
0.0.0.0 site676.net
@@||SITE459.NET^
127.0.0.1 site777.com # note
||site1404.co.uk^
@@||site1417.example^
0.0.0.0 site2892.io
||site1039.co.uk^
||site1648.org
||SITE1349.IO
||site76.test
||site2051.co.uk
||site676.net
0.0.0.0 sub4.site1909.org
||site157.co.uk^
0.0.0.0 site1735.com
0.0.0.0 site545.test
||site1912.net^
0.0.0.0 site174.co.uk
||site67.io^
||site1643.test^
0.0.0.0 site758.com
||site524.co.uk^
site1604.com
site2174.io
site1246.org
@@||SITE779.COM^
||site2613.org^
site2348.com
||site76.test^
||site2148.test^
site1348.com
127.0.0.1 site2473.example # note
@@||site2892.io^
||site2964.com^
||site620.org^
site2696.org
0.0.0.0 site333.org
||site345.co.uk^
||SITE928.IO^
||site2791.org
0.0.0.0 site471.example
||site2668.co.uk^
||site952.com
||site1606.com^
@@||site502.co.uk^
0.0.0.0 site1562.test
||site993.co.uk
0.0.0.0 site1921.org
||site183.net
localhost
0.0.0.0
127.0.0.1 localhost
::1 ip6-localhost
bad rule here
||
@@||
! c
# c

  
`,
}

// rustFixtureVerdicts are what the Rust server answered for POST /api/filter/check,
// one per behaviour class of the original 3866 queries (two for a class of 25 or
// more): outcome, reporting list, query case, and for each list whether a matching
// rule allows or blocks and whether it matches exactly, as a subdomain rule, or both.
// The last rows are queries that miss: a single label, and a parent of a rule.
var rustFixtureVerdicts = []struct {
	domain  string
	blocked bool
	list    string
	rule    string
}{
	{"sub0.site2045.example", true, "fx2", "site2045.example"},
	{"sub1.site608.com", true, "fx2", "site608.com"},
	{"SITE2676.CO.UK", false, "", ""},
	{"SUB0.SITE403.ORG", false, "", ""},
	{"a.b.site183.net", true, "fx3", "site183.net"},
	{"site1473.org", false, "", "site1473.org"},
	{"unlisted654986.example.invalid", false, "", ""},
	{"sub0.site1533.org", true, "fx1", "sub0.site1533.org"},
	{"a.b.site835.io", false, "", ""},
	{"SITE1039.CO.UK", true, "fx2", "site1039.co.uk"},
	{"site1973.io", true, "fx3", "site1973.io"},
	{"site1975.com", true, "fx1", "site1975.com"},
	{"sub1.site111.com", true, "fx3", "site111.com"},
	{"site354.example", true, "fx2", "site354.example"},
	{"sub3.site243.co.uk", true, "fx3", "site243.co.uk"},
	{"site2683.org", true, "fx3", "site2683.org"},
	{"a.b.site1620.com", true, "fx2", "site1620.com"},
	{"a.b.site1807.io", true, "fx3", "site1807.io"},
	{"sub4.site133.net", true, "fx3", "site133.net"},
	{"a.b.site2240.io", true, "fx1", "site2240.io"},
	{"a.b.site1503.example", true, "fx2", "site1503.example"},
	{"sub0.site667.example", true, "fx1", "site667.example"},
	{"site2174.io", true, "fx3", "site2174.io"},
	{"SUB0.SITE1766.EXAMPLE", true, "fx1", "site1766.example"},
	{"SUB4.SITE1663.EXAMPLE", true, "fx3", "site1663.example"},
	{"site550.net", true, "fx3", "site550.net"},
	{"site829.co.uk", true, "fx1", "site829.co.uk"},
	{"site232.example", true, "fx3", "site232.example"},
	{"SUB3.SITE1999.ORG", true, "fx3", "site1999.org"},
	{"SITE2017.CO.UK", true, "fx1", "site2017.co.uk"},
	{"site1774.net", true, "fx2", "site1774.net"},
	{"site2224.com", true, "fx3", "site2224.com"},
	{"site2328.io", false, "", "site2328.io"},
	{"site613.example", true, "fx2", "site613.example"},
	{"SITE2751.TEST", true, "fx3", "site2751.test"},
	{"site2685.io", false, "", "site2685.io"},
	{"site2529.io", true, "fx1", "site2529.io"},
	{"SUB3.SITE2368.CO.UK", true, "fx2", "site2368.co.uk"},
	{"site2119.io", true, "fx3", "site2119.io"},
	{"site1921.org", true, "fx1", "site1921.org"},
	{"SUB4.SITE840.COM", true, "fx1", "sub4.site840.com"},
	{"site273.example", false, "", "site273.example"},
	{"site219.co.uk", true, "fx3", "site219.co.uk"},
	{"site471.example", true, "fx1", "site471.example"},
	{"site326.test", false, "", "site326.test"},
	{"site191.org", true, "fx1", "site191.org"},
	{"sub1.site246.io", true, "fx3", "site246.io"},
	{"site1007.test", true, "fx3", "site1007.test"},
	{"site974.io", true, "fx2", "site974.io"},
	{"site2794.example", true, "fx1", "site2794.example"},
	{"SITE827.ORG", true, "fx1", "site827.org"},
	{"SUB2.SITE2582.TEST", false, "", "site2582.test"},
	{"SITE2164.EXAMPLE", true, "fx1", "site2164.example"},
	{"site2532.example", true, "fx3", "site2532.example"},
	{"site2668.co.uk", false, "", "site2668.co.uk"},
	{"site633.test", true, "fx2", "site633.test"},
	{"SITE757.EXAMPLE", true, "fx2", "site757.example"},
	{"site2214.com", true, "fx2", "site2214.com"},
	{"sub2.site2178.example", true, "fx2", "site2178.example"},
	{"site2483.io", true, "fx1", "site2483.io"},
	{"a.b.site2613.org", false, "", "site2613.org"},
	{"SUB3.SITE2220.IO", true, "fx2", "site2220.io"},
	{"SUB4.SITE23.ORG", true, "fx2", "sub4.site23.org"},
	{"sub3.site2901.io", true, "fx2", "site2901.io"},
	{"site2702.example", true, "fx2", "site2702.example"},
	{"sub0.site2791.org", true, "fx3", "site2791.org"},
	{"SUB4.SITE2851.NET", true, "fx3", "sub4.site2851.net"},
	{"a.b.site1811.org", false, "", "site1811.org"},
	{"SITE2391.ORG", true, "fx3", "site2391.org"},
	{"site89.net", false, "", "site89.net"},
	{"site419.io", true, "fx1", "site419.io"},
	{"site2896.test", true, "fx2", "site2896.test"},
	{"site1411.example", true, "fx1", "site1411.example"},
	{"SUB1.SITE1790.NET", true, "fx3", "site1790.net"},
	{"site853.test", true, "fx2", "site853.test"},
	{"sub3.site2680.example", false, "", "site2680.example"},
	{"site1428.org", true, "fx1", "site1428.org"},
	{"site2582.test", false, "", "site2582.test"},
	{"site2363.com", true, "fx3", "site2363.com"},
	{"SUB2.SITE1136.CO.UK", true, "fx3", "site1136.co.uk"},
	{"sub4.site1404.co.uk", true, "fx1", "sub4.site1404.co.uk"},
	{"a.b.site345.co.uk", false, "", "site345.co.uk"},
	{"site871.example", false, "", "site871.example"},
	{"sub0.site2671.org", false, "", "site2671.org"},
	{"site1930.com", false, "", "site1930.com"},
	{"site927.net", true, "fx2", "site927.net"},
	{"SITE1876.IO", true, "fx1", "site1876.io"},
	{"site917.co.uk", false, "", "site917.co.uk"},
	{"SITE637.CO.UK", true, "fx1", "site637.co.uk"},
	{"site2883.io", true, "fx2", "site2883.io"},
	{"a.b.site2070.org", true, "fx3", "site2070.org"},
	{"a.b.site1417.example", false, "", "site1417.example"},
	{"site993.co.uk", true, "fx1", "site993.co.uk"},
	{"a.b.site1385.org", false, "", "site1385.org"},
	{"site456.net", true, "fx1", "site456.net"},
	{"sub0.site1564.co.uk", true, "fx3", "site1564.co.uk"},
	{"site2756.co.uk", true, "fx2", "site2756.co.uk"},
	{"a.b.site2892.io", false, "", "site2892.io"},
	{"a.b.site702.com", false, "", "site702.com"},
	{"site1580.io", true, "fx3", "site1580.io"},
	{"site621.co.uk", true, "fx3", "site621.co.uk"},
	{"site157.co.uk", true, "fx3", "site157.co.uk"},
	{"SITE1187.TEST", true, "fx1", "site1187.test"},
	{"SITE1585.ORG", true, "fx3", "site1585.org"},
	{"site2550.example", true, "fx2", "site2550.example"},
	{"site1851.co.uk", false, "", "site1851.co.uk"},
	{"SITE758.COM", true, "fx1", "site758.com"},
	{"SITE1117.CO.UK", true, "fx3", "site1117.co.uk"},
	{"site1947.io", true, "fx1", "site1947.io"},
	{"site1183.test", true, "fx3", "site1183.test"},
	{"a.b.site2015.net", true, "fx1", "site2015.net"},
	{"site120.io", true, "fx1", "site120.io"},
	{"site155.test", false, "", "site155.test"},
	{"sub1.site238.org", true, "fx2", "sub1.site238.org"},
	{"a.b.site139.org", true, "fx3", "site139.org"},
	{"SITE435.ORG", true, "fx1", "site435.org"},
	{"site1642.com", false, "", "site1642.com"},
	{"a.b.site620.org", true, "fx3", "site620.org"},
	{"SITE2224.COM", true, "fx3", "site2224.com"},
	{"SITE1811.ORG", false, "", "site1811.org"},
	{"site174.co.uk", true, "fx3", "site174.co.uk"},
	{"site1258.co.uk", false, "", "site1258.co.uk"},
	{"SITE1371.COM", true, "fx2", "site1371.com"},
	{"site1336.net", false, "", "site1336.net"},
	{"a.b.site1535.io", false, "", "site1535.io"},
	{"site2578.example", true, "fx2", "site2578.example"},
	{"SITE702.COM", false, "", "site702.com"},
	{"site2945.net", true, "fx1", "site2945.net"},
	{"sub1.site2725.org", false, "", "site2725.org"},
	{"site820.co.uk", false, "", "site820.co.uk"},
	{"SUB4.SITE672.ORG", true, "fx2", "site672.org"},
	{"site251.org", true, "fx1", "site251.org"},
	{"SITE1393.NET", false, "", "site1393.net"},
	{"SITE2011.NET", false, "", "site2011.net"},
	{"site2696.org", false, "", "site2696.org"},
	{"site676.net", true, "fx3", "site676.net"},
	{"site620.org", true, "fx3", "site620.org"},
	{"site2070.org", true, "fx3", "site2070.org"},
	{"SUB2.SITE492.ORG", true, "fx2", "site492.org"},
	{"sub3.site2950.com", false, "", "site2950.com"},
	{"site590.io", true, "fx1", "site590.io"},
	{"sub1.site952.com", true, "fx3", "site952.com"},
	{"SITE524.CO.UK", true, "fx3", "site524.co.uk"},
	{"SUB3.SITE118.IO", false, "", "site118.io"},
	{"SITE315.IO", true, "fx1", "site315.io"},
	{"sub0.site77.io", true, "fx3", "sub0.site77.io"},
	{"SUB1.SITE2680.EXAMPLE", false, "", "site2680.example"},
	{"SITE1684.IO", true, "fx3", "site1684.io"},
	{"site2385.co.uk", false, "", "site2385.co.uk"},
	{"sub3.site2582.test", false, "", "site2582.test"},
	{"SITE286.COM", true, "fx1", "site286.com"},
	{"site1901.test", true, "fx3", "site1901.test"},
	{"site831.net", true, "fx2", "site831.net"},
	{"SITE1804.COM", true, "fx1", "site1804.com"},
	{"site545.test", true, "fx3", "site545.test"},
	{"site76.test", true, "fx1", "site76.test"},
	{"SITE1535.IO", false, "", "site1535.io"},
	{"SUB3.SITE2847.EXAMPLE", false, "", "site2847.example"},
	{"a.b.site2269.org", false, "", "site2269.org"},
	{"site1225.example", true, "fx1", "site1225.example"},
	{"site1096.co.uk", true, "fx2", "site1096.co.uk"},
	{"SITE1906.EXAMPLE", true, "fx2", "site1906.example"},
	{"SITE2798.IO", true, "fx2", "site2798.io"},
	{"site2613.org", false, "", "site2613.org"},
	{"SUB4.SITE1315.IO", false, "", "site1315.io"},
	{"site384.example", true, "fx1", "site384.example"},
	{"SITE2555.ORG", true, "fx1", "site2555.org"},
	{"SITE331.COM", false, "", "site331.com"},
	{"site1335.co.uk", true, "fx2", "site1335.co.uk"},
	{"sub0.site1315.io", false, "", "site1315.io"},
	{"site2747.test", false, "", "site2747.test"},
	{"site452.org", true, "fx2", "site452.org"},
	{"SITE2725.ORG", false, "", "site2725.org"},
	{"SITE1648.ORG", true, "fx1", "site1648.org"},
	{"sub3.site2974.com", true, "fx1", "sub3.site2974.com"},
	{"site777.com", true, "fx2", "site777.com"},
	{"site1905.net", true, "fx1", "site1905.net"},
	{"a.b.site0.io", true, "fx3", "site0.io"},
	{"SUB0.SITE1924.NET", true, "fx2", "site1924.net"},
	{"sub2.site1398.co.uk", false, "", "sub2.site1398.co.uk"},
	{"sub3.site156.org", true, "fx1", "sub3.site156.org"},
	{"SUB1.SITE1245.IO", false, "", "site1245.io"},
	{"a.b.site2607.io", false, "", "site2607.io"},
	{"site2572.co.uk", true, "fx2", "site2572.co.uk"},
	{"site9.example", true, "fx1", "site9.example"},
	{"site2837.net", true, "fx1", "site2837.net"},
	{"sub2.site2866.example", true, "fx2", "site2866.example"},
	{"sub1.site779.com", false, "", "site779.com"},
	{"a.b.site1519.example", false, "", "site1519.example"},
	{"site2148.test", false, "", "site2148.test"},
	{"sub2.site1606.com", false, "", "site1606.com"},
	{"site1349.io", true, "fx2", "site1349.io"},
	{"SITE1067.EXAMPLE", true, "fx3", "site1067.example"},
	{"site2831.co.uk", false, "", "site2831.co.uk"},
	{"site2289.co.uk", false, "", "site2289.co.uk"},
	{"site67.io", true, "fx2", "site67.io"},
	{"site1701.co.uk", false, "", "site1701.co.uk"},
	{"SUB0.SITE1571.COM", true, "fx3", "sub0.site1571.com"},
	{"site661.io", true, "fx3", "site661.io"},
	{"site2348.com", true, "fx2", "site2348.com"},
	{"site782.test", false, "", "site782.test"},
	{"site649.com", true, "fx1", "site649.com"},
	{"SUB1.SITE521.IO", false, "", "site521.io"},
	{"SITE1513.TEST", true, "fx2", "site1513.test"},
	{"sub1.site928.io", false, "", "site928.io"},
	{"site2411.test", true, "fx2", "site2411.test"},
	{"sub1.site612.net", false, "", "site612.net"},
	{"SITE1955.TEST", false, "", "site1955.test"},
	{"site1315.io", false, "", "site1315.io"},
	{"SITE1970.ORG", false, "", "site1970.org"},
	{"site2959.test", false, "", "site2959.test"},
	{"sub2.site705.org", true, "fx2", "site705.org"},
	{"site333.org", false, "", "site333.org"},
	{"sub1.site2426.org", true, "fx3", "sub1.site2426.org"},
	{"SUB4.SITE1909.ORG", true, "fx3", "sub4.site1909.org"},
	{"SITE1348.COM", true, "fx1", "site1348.com"},
	{"SUB1.SITE2127.CO.UK", false, "", "site2127.co.uk"},
	{"site2473.example", true, "fx1", "site2473.example"},
	{"site774.org", true, "fx1", "site774.org"},
	{"SITE2051.CO.UK", true, "fx2", "site2051.co.uk"},
	{"a.b.site1980.co.uk", false, "", "site1980.co.uk"},
	{"site2982.org", false, "", "site2982.org"},
	{"SITE1875.ORG", false, "", "site1875.org"},
	{"site1562.test", false, "", "site1562.test"},
	{"site2802.io", false, "", "site2802.io"},
	{"site428.net", true, "fx1", "site428.net"},
	{"site1912.net", true, "fx3", "site1912.net"},
	{"site1604.com", false, "", "site1604.com"},
	{"site1246.org", true, "fx1", "site1246.org"},
	{"SUB2.SITE558.TEST", true, "fx2", "site558.test"},
	{"site2964.com", true, "fx1", "site2964.com"},
	{"sub3.site71.io", true, "fx1", "site71.io"},
	{"SITE1609.EXAMPLE", true, "fx3", "site1609.example"},
	{"SUB3.SITE2637.NET", false, "", "site2637.net"},
	{"sub3.site334.org", true, "fx3", "site334.org"},
	{"site2725.org", false, "", "site2725.org"},
	{"SITE1697.COM", true, "fx1", "site1697.com"},
	{"site64.io", false, "", "site64.io"},
	{"site280.com", true, "fx3", "site280.com"},
	{"SITE1598.CO.UK", true, "fx2", "site1598.co.uk"},
	{"site1735.com", true, "fx2", "site1735.com"},
	{"SUB4.SITE1822.CO.UK", true, "fx1", "sub4.site1822.co.uk"},
	{"sub2.site330.net", true, "fx1", "site330.net"},
	{"sub0.site1483.com", false, "", "site1483.com"},
	{"SUB1.SITE976.IO", true, "fx3", "site976.io"},
	{"site773.org", true, "fx1", "site773.org"},
	{"site2757.io", true, "fx1", "site2757.io"},
	{"sub3.site49.co.uk", true, "fx3", "site49.co.uk"},
	{"a.b.site459.net", false, "", "site459.net"},
	{"SITE2219.CO.UK", true, "fx2", "site2219.co.uk"},
	{"sub3.site1864.test", true, "fx1", "sub3.site1864.test"},
	{"sub0.site443.org", true, "fx2", "sub0.site443.org"},
	{"sub4.site521.io", false, "", "site521.io"},
	{"SITE384.EXAMPLE", true, "fx1", "site384.example"},
	{"a.b.site506.co.uk", true, "fx3", "site506.co.uk"},
	{"sub0.site1633.example", true, "fx2", "site1633.example"},
	{"SITE2362.ORG", false, "", "site2362.org"},
	{"site2750.io", true, "fx1", "site2750.io"},
	{"site1606.com", false, "", "site1606.com"},
	{"sub0.site502.co.uk", false, "", "site502.co.uk"},
	{"SUB0.SITE1115.TEST", true, "fx2", "site1115.test"},
	{"site1525.net", true, "fx1", "site1525.net"},
	{"site2185.co.uk", true, "fx1", "site2185.co.uk"},
	{"site506.co.uk", true, "fx1", "site506.co.uk"},
	{"site395.io", true, "fx2", "site395.io"},
	{"sub1.site2522.net", true, "fx3", "site2522.net"},
	{"SUB3.SITE2016.COM", true, "fx1", "sub3.site2016.com"},
	{"a.b.site557.test", false, "", "site557.test"},
	{"a.b.site234.org", true, "fx3", "site234.org"},
	{"site1519.example", false, "", "site1519.example"},
	{"SITE333.ORG", false, "", "site333.org"},
	{"SUB3.SITE332.EXAMPLE", false, "", "site332.example"},
	{"site1896.test", true, "fx3", "site1896.test"},
	{"SITE1930.COM", false, "", "site1930.com"},
	{"site1643.test", false, "", "site1643.test"},
	{"SUB4.SITE817.NET", true, "fx1", "site817.net"},
	{"sub1.site167.net", false, "", "sub1.site167.net"},
	{"site2892.io", false, "", "site2892.io"},
	{"site1115.test", true, "fx2", "site1115.test"},
	{"site2450.io", true, "fx1", "site2450.io"},
	{"site1398.co.uk", true, "fx2", "site1398.co.uk"},
	{"site1434.io", false, "", "site1434.io"},
	{"a.b.site2667.org", false, "", "site2667.org"},
	{"site2115.org", true, "fx1", "site2115.org"},
	{"site2476.test", false, "", "site2476.test"},
	{"io", false, "", ""},
	{"co.uk", false, "", ""},
}
