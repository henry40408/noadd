package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPolicyLengthMessages(t *testing.T) {
	cases := []struct{ password, want string }{
		{strings.Repeat("a", 11), "password must be at least 12 characters"},
		{strings.Repeat("a", 129), "password must be at most 128 characters"},
		// Characters, not bytes: 11 CJK characters are 33 bytes.
		{strings.Repeat("密", 11), "password must be at least 12 characters"},
	}
	for _, c := range cases {
		err := ValidatePolicy(c.password)
		var policy *PolicyError
		if !errors.As(err, &policy) || policy.Message != c.want {
			t.Errorf("%d bytes: err = %v, want %q", len(c.password), err, c.want)
		}
	}
}

func TestPolicyAcceptsAStrongPassphrase(t *testing.T) {
	if err := ValidatePolicy("zx-initial-Strong-passphrase-9143-lamp", "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRejectionWording(t *testing.T) {
	err := ValidatePolicy("password1234", "admin")
	want := "password rejected: it is too easy to guess. Use a longer passphrase of several unrelated words."
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v", err)
	}
}

// rustPolicyVerdicts are the Rust zxcvbn 3.1 verdicts captured from release
// 0.41.1 over POST /api/users/me/password (username "admin", accepted when the
// score is at least 3). Only accept/reject is observable there, so only that is
// compared. They are never regenerated from Go output.
var rustPolicyVerdicts = []struct {
	password string
	accepted bool
}{
	{"password1234", false},
	{"password12345", false},
	{"123456789012", false},
	{"qwertyuiop12", false},
	{"iloveyou1234", false},
	{"letmein123456", false},
	{"administrator", false},
	{"adminadmin123", false},
	{"welcome12345", false},
	{"monkey1234567", false},
	{"dragon1234567", false},
	{"football12345", false},
	{"baseball12345", false},
	{"passw0rd1234", false},
	{"trustno1trustno1", false},
	{"1q2w3e4r5t6y", false},
	{"qazwsxedcrfv", false},
	{"asdfghjklzxc", false},
	{"zxcvbnmasdfg", false},
	{"qwertyqwerty", false},
	{"abcdefghijkl", false},
	{"abc123abc123", false},
	{"111111111111", false},
	{"000000000000", false},
	{"123123123123", false},
	{"password-password", true},
	{"Password123456", false},
	{"Password1234!", false},
	{"Admin123456789", false},
	{"Welcome2024!!", true},
	{"Summer2024!!!!", true},
	{"Spring2023!!!!", true},
	{"Winter2022!!!!", true},
	{"P@ssw0rd12345", false},
	{"P@ssw0rd!2024", false},
	{"changeme12345", false},
	{"superman12345", false},
	{"batman123456", false},
	{"starwars12345", false},
	{"pokemon123456", false},
	{"michael123456", false},
	{"jennifer12345", false},
	{"charlie123456", false},
	{"shadow1234567", false},
	{"master1234567", false},
	{"sunshine12345", false},
	{"princess12345", false},
	{"whatever12345", false},
	{"freedom12345", false},
	{"computer1234", false},
	{"internet1234", false},
	{"noadd-admin-1", true},
	{"noaddnoaddnoadd", false},
	{"adminadminadmin", false},
	{"useruseruser12", false},
	{"rootrootroot12", false},
	{"raspberrypi123", true},
	{"qwertyuiopasdf", false},
	{"1234567890qwer", false},
	{"asdfghjkl;'zxcv", false},
	{"zaq12wsxcde3", false},
	{"1qaz2wsx3edc4rfv", false},
	{"poiuytrewqlkjh", false},
	{"!QAZ2wsx#EDC4rfv", true},
	{"qwerty123456!", false},
	{"azertyuiop123", false},
	{"mnbvcxzlkjhg", false},
	{"147258369147", false},
	{"789456123789", false},
	{"159753456852", false},
	{"aaaaaaaaaaaa", false},
	{"abababababab", false},
	{"xyzxyzxyzxyz", false},
	{"1111aaaa2222", false},
	{"qqqqwwwweeee", false},
	{"09876543210987", false},
	{"qwe123qwe123", false},
	{"我愛你我愛你我愛你我愛你", false},
	{"密碼密碼密碼密碼密碼密碼", false},
	{"今天天氣很好我們去公園玩", true},
	{"台北一零一大樓真的很高啊", true},
	{"パスワードパスワードパスワード", false},
	{"これは長い日本語のパスワード", true},
	{"한국어비밀번호는길게만든다", true},
	{"你好世界你好世界你好世界", false},
	{"春夏秋冬東西南北中發白青", true},
	{"中文密碼123456789", false},
	{"密碼Password123", false},
	{"紅色的蘋果掉落在綠色草地上", true},
	{"臺灣是個美麗的寶島嶼國家", true},
	{"咖啡與書本還有安靜的午後", true},
	{"1234567890中文密碼", false},
	{"小明小華小美小強小芳小英", true},
	{"鍵盤上的字母排列方式不同", true},
	{"mountain-tunnel", true},
	{"orangesponge", false},
	{"meadowvessel", false},
	{"parcelthunder", false},
	{"purplewizard", false},
	{"orange_marble", true},
	{"timberwizard", false},
	{"umbrellagarden", false},
	{"vessel staple umbrella", true},
	{"tunnel.staple.lantern", true},
	{"timberrivercactus", true},
	{"mountain_sponge_garden", true},
	{"walnut.timber.pencil", true},
	{"vesselumbrellablanket", true},
	{"window-timber-orange", true},
	{"staple.pickle.thunder", true},
	{"sponge_wizard_button_zipper", true},
	{"zipper.meadow.walnut.marble", true},
	{"marble purple umbrella walnut", true},
	{"ribbon.anchor.yellow.cactus", true},
	{"orange.garden.parcel.velvet", true},
	{"anchor mountain ribbon velvet", true},
	{"orangetimberumbrellabutton", true},
	{"falcon-whistle-ribbon-vessel", true},
	{"orange_purple_harbor_kettle_staple", true},
	{"umbrella-yellow-cactus-saddle-falcon", true},
	{"zipperfalconcandlepicklegarden", true},
	{"staple_thunder_cactus_river_marble", true},
	{"tunnel_ribbon_purple_candle_yellow", true},
	{"timber_harbor_river_wizard_velvet", true},
	{"saddle-lantern-mountain-purple-pencil", true},
	{"lantern correct ribbon vessel pencil", true},
	{"cactus-correct-mountain-velvet-sponge-meadow", true},
	{"umbrella.button.river.parcel.staple.zipper", true},
	{"tunnel.pickle.whistle.vessel.window.kettle", true},
	{"staple_blanket_orange_thunder_yellow_candle", true},
	{"anchorwhistlestaplewindowcorrectmountain", true},
	{"window.meadow.horse.orange.thunder.saddle", true},
	{"violin falcon meadow kettle garden timber", true},
	{"zipper_kettle_whistle_walnut_purple_mountain", true},
	{"correct horse battery staple", true},
	{"Tr0ub4dor&3xxxx", true},
	{"thequickbrownfoxjumps", true},
	{"Thequickbrownfox1!", true},
	{"to be or not to be that is", true},
	{"ilovemydogandmycat", true},
	{"myhorsehasthreelegs", true},
	{"ihatemondaymornings", true},
	{"admin admin admin admin", false},
	{"hello world hello world", true},
	{"dxkxipwfqagq", true},
	{"lewrayqjucwi", true},
	{"qlflyhrryqku", true},
	{"htzzygzhmxzh", true},
	{"gqplxaazipig", true},
	{"wtlozxllchdh", true},
	{"pgkgpttapulzu", true},
	{"cvdmzwygpfnzu", true},
	{"kczxmomxcxffe", true},
	{"aesozuettpvler", true},
	{"reaazxudqxengg", true},
	{"aigjqhyskirneb", true},
	{"xlovsqnqereqqaoy", true},
	{"ftayzefeptxdrbkv", true},
	{"qqrpzydrbhgibydq", true},
	{"oraycoktqtqgwioqrzpq", true},
	{"hwqirgoendmokcvhncgv", true},
	{"jzdyewuvleieohxdmpfv", true},
	{"hfwnqmknglkcxlakroowamkq", true},
	{"tjqcdzhdciibyfiyenvimerq", true},
	{"spwkcibzwfnciauczicthcid", true},
	{"oakrnitebqwhdfibfgjujqygjoqvfilz", true},
	{"aibaaxqrgqphodvunvprmqjwghkgwxue", true},
	{"mlbeacuxinfbcvmqvjthwjboffioailk", true},
	{"PFeNBTxaQWk8", true},
	{"J#zF#alHlsZf", true},
	{"YcMMDk^tXP@t", true},
	{"Ksf$2#r^#cDkdf", true},
	{"rUnW5gc&F!Ha6i", true},
	{"#&l^i8GjHEAD6@", true},
	{"Wj9KfzjsQGMrb9h!", true},
	{"ImB!L%K777pzNk8c", true},
	{"L6j#5IXAAjls^HUq", true},
	{"$JoUD@!Ydua!5ZMs1SWO", true},
	{"pQaPRYpzbLGViYXjU2Jg", true},
	{"JngKtFI3$OyV2dZAkg05", true},
	{"adminadmin1234", false},
	{"admin1234567890", false},
	{"Admin!Admin!Admin!", false},
	{"nimda1234567890", false},
	{"administrator1", false},
	{"admin-2024-admin", true},
	{"adminpassword12", false},
	{"passwordadmin12", false},
	{"admin2024admin2024", false},
	{"Adm1n-Adm1n-Adm1n", false},
	{"19900101199001", true},
	{"01011990010119", true},
	{"20240101abcdef", false},
	{"12251999Xmas!!", true},
	{"19851231Birthday", false},
	{"Jan2024Jan2024Jan", true},
	{"1999-12-31-1999", true},
	{"2000-01-01-abcd", true},
}

func TestPolicyParityWithRust(t *testing.T) {
	var mismatches []string
	for _, c := range rustPolicyVerdicts {
		if accepted := ValidatePolicy(c.password, "admin") == nil; accepted != c.accepted {
			mismatches = append(mismatches, c.password)
		}
	}
	t.Logf("%d of %d verdicts differ from Rust", len(mismatches), len(rustPolicyVerdicts))
	if len(mismatches) > 0 {
		t.Logf("differing passwords: %q", mismatches)
	}
	// Plan section 7 decision 3 accepts the Go score where the libraries
	// disagree; this bound only catches a gross regression of the port.
	if limit := len(rustPolicyVerdicts) / 4; len(mismatches) > limit {
		t.Fatalf("%d mismatches exceed %d", len(mismatches), limit)
	}
}
