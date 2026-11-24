package views

// goldenDigests holds the sha256 of each page the Rust server 0.41.1 rendered
// (ghcr.io/henry40408/noadd:0.41.1, host 127.0.0.1:19080, client
// 192.168.215.1, plain HTTP), after normalize. The names: <page>_empty is a
// fresh database and <page>_data the state of rust-v17.sqlite3 (legacySQL in
// internal/db); the rest are variants (logs_filtered, logs_wildcard,
// logs_bad_page, filters_edit, filters_test_*, registry_search,
// registry_load_failed with the registry host unreachable, account_confirm_delete,
// stats_30d, the <name>_error pages, account_api_key_created) and flash_<name>,
// each of the nine flashes on the dashboard. Where two names share a digest
// the pages are byte for byte the same. The registry pages used the live
// AdGuard registry, held in registryFilters.
//
// Do not recompute a digest to make a test pass: it is the Rust server's page.
var goldenDigests = map[string]string{
	"account_api_key_created":  "33e2aa06617030e021d77a0da33ba02ec3bf9c79b6cbb592cf01ef135ebf80c8",
	"account_api_key_error":    "fda5fe9347d25ea972d5dffe5f70aa3f506aeeb16ebf8a22c34d13991fb8be18",
	"account_confirm_delete":   "64dd945b54891c3c449235590468471c5c435803582f25bf8e011d9d693a98dd",
	"account_data":             "d0eb9d5daddc3542b4af49cd12791cc72794539ea763ee6ff46f38ce007e3439",
	"account_empty":            "7d72404daa5d82a2916edc48bf175dd6b6de62865c268f5b14864c8c23b5f5a1",
	"account_operator_error":   "2d926187f775e9c6a8bd28cc0b2e2a453a478d564d56ffaae6d20a5e761c8f0f",
	"dashboard_data":           "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"dashboard_empty":          "9909332456479f0a5ee1260b4d4896d1d5707c34ff048d105821eec9532bb676",
	"dashboard_welcome":        "0cdc674bef3bf01ccf26cb34e45240bb665d95b3fbc2ae13e2f7b0c148bca08b",
	"filters_add_list_error":   "a551316b2de8bc6880c1e24607d18159f335ead6baed5d6b95c6534024146db1",
	"filters_add_rule_error":   "7e4ed85f8c64c7bc490b0dcf7325f13a01a9d5a7b6c0fba042ce6088028175a3",
	"filters_data":             "61c7a3bbe06bf59bc0723b6843fe987154a176a41364b2ff9ac8a116b0835c7f",
	"filters_edit":             "47a7f3731612a71a671e41cd42c2b408ccf5fc5b78b4d0abbe6958528f74b80b",
	"filters_edit_error":       "fd0fd493e320968c2e4df1a5bcbe5af1559e83bcbe7f5a81745d980d0a12cc98",
	"filters_empty":            "9bbe43addcf0bddfc7276be57eff76319514c4942bb920e55951215fecc52422",
	"filters_test_allowed":     "e4589472e81c0fd7aa220fe1074088af62ce2f9c94667d7042215b3a96153fd4",
	"filters_test_blocked":     "b8f5272be694521248154c9ca3dbd0704c619b38de5b23b0388a8b5f094a1ddd",
	"filters_test_none":        "cb0585d144b1be1f7a7c6d179b79853b30d8d4008c41eeb505e7c9b362fce610",
	"flash_account_saved":      "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_filters_saved":      "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_lists_updating":     "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_logs_cleared":       "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_password_changed":   "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_proxy_logout":       "81ff77ed39d3e7bbb4c0a840c3bacf00582f346da034a186aa29113c8fc87ccc",
	"flash_sessions_revoked":   "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_settings_saved":     "794ee5f67fe284b3aa0f3f2c85cb06377445b7a5b9b77ec9a5921fa6b3b56230",
	"flash_welcome":            "b4fa27d40745db10f16fbb86db597d30ff071301ce89ed2b93e049b32a8b7fbb",
	"login_error":              "bafa1e2e3c49b1783bc472a94265049da1602a6f2a4e01061e91ee884c0e8775",
	"login_page":               "bb492557dbf9d145a9251491a71d2a5e890bb0d8ead9c2905f6abf0d04c3ac68",
	"logs_bad_page":            "ea5623621f2acb11522f262f8b48aec774d85a7d8f777e36eb556aee8b56b042",
	"logs_data":                "ea5623621f2acb11522f262f8b48aec774d85a7d8f777e36eb556aee8b56b042",
	"logs_empty":               "917e1835f917a98562b298c4c42d36d65ea2236a0cef6c23e5b38f303482fc52",
	"logs_filtered":            "b7fe532e5e86f7eafc0cfc47eed381690782228034359df5fe781730d5dd8681",
	"logs_wildcard":            "924d7d40ff50d7a59dfdbdb254741e8db232a4a662e7a2661435f8e63fc2e25f",
	"registry_add_load_failed": "9fc234f1e6e70935f6c314fd17b339b96f8a875dc4ac2b14411883dc23eeacd6",
	"registry_add_none":        "d84cbe8afba4b0743269d056255afa453a9bc9589c53c2ae80c72ad7c761969a",
	"registry_data":            "ef5d2f2086247d0da086571300408d273f0bc7ccac7e1b0b13c7440a48511091",
	"registry_empty":           "2ef34161eb109e7965ebee832cf74ecff0f22e45c3f3c6fd14b81783fdc0aa48",
	"registry_load_failed":     "635bc0293f86e682d1dc4cd90e45dd665f5ce1ae202dcc0a19652879811f873e",
	"registry_search":          "9c4875f62ca614f832ba86701bdfa8497ba8659460ca1dc88a7a6d6c1c30f971",
	"settings_data":            "2f4612514e6f9ddc0d4a7a8ebcd356d1da414c16dcab48dd87088c1d3ebf58a7",
	"settings_empty":           "82fab42c1ab8fa7324fc6feef44e2567597cc01fc55e28b717429b1ea31d04c1",
	"settings_error":           "7c7d80adc515a95f94c72303d1e480d6e7d83bc237fbe4a807ba17388a888ce9",
	"setup_empty":              "5ea2feb40db327384be6dcdeb142becb02c20fe33d60ac65cbdce9e9ae48b1bf",
	"setup_error_bad_token":    "72917567bca69a023b3aa908e31977eea752c898c91bf95ae33beada4b90699b",
	"setup_error_mismatch":     "5ded811602a469c88551b654cd4d63de19593148a07df163efe485c13cd32de4",
	"setup_error_weak":         "d67a72b98a6d72b7fe0ac6c96b38464dd5cdf030e76be80c42737be977db1709",
	"stats_30d":                "47f5079b6b908b5e8ed59fea226523f1506ff968f5f37ba9ad062786d84c5702",
	"stats_data":               "58090ff5478e5ba4a69a8921d032c678dcdf428d8628543e289b67bc2d22a36b",
	"stats_empty":              "c42c42896372bdfb3e16d7ead95d8d97d391185aa104b5e8224da6833f82c217",
}
