/* HardID — multi-language strings. Copyright (C) 2026 LightningASIC.
 * License: Apache License 2.0.
 *
 * The order of s_labels MUST match lang_key_t in lang.h exactly. Every
 * glyph used by CJK strings must exist in font_cjk.c (regenerate via
 * /tmp/gen_cjk.py after editing these strings).
 */

#include <stddef.h>
#include "lang.h"
#include "nvs_flash.h"

#define LANG_NVS_NS   "hardid"
#define LANG_NVS_KEY  "lang"

static lang_id_t s_lang = LANG_EN;

/* Menu labels, one row per key, one column per language (EN/ZH/JA/KO).
 * UTF-8 encoded; the CJK subset font covers every glyph used here. */
static const char *const s_labels[LKEY_COUNT][LANG_COUNT] = {
	/* LKEY_INITIALIZE */      { "INITIALIZE",   "初始化",     "初期化",        "초기화" },
	/* LKEY_RECOVER */         { "RECOVER",      "恢复",       "復元",          "복구" },
	/* LKEY_SIGN */            { "SIGN",         "签名",       "署名",          "서명" },
	/* LKEY_HOST_LINK */       { "HOST LINK",    "主机连接",   "ホスト接続",    "호스트 연결" },
	/* LKEY_FIDO */            { "FIDO",         "FIDO",       "FIDO",          "FIDO" },
	/* LKEY_APP_MARKET */      { "APP MARKET",   "应用市场",   "アプリ市場",    "앱 마켓" },
	/* LKEY_PIN */             { "PIN",          "PIN",        "PIN",           "PIN" },
	/* LKEY_ABOUT */           { "ABOUT",        "关于",       "情報",          "정보" },
	/* LKEY_FACTORY_RESET */   { "FACTORY RESET", "恢复出厂设置", "工場出荷時リセット", "공장 초기화" },
	/* LKEY_LANGUAGE */        { "LANGUAGE",     "语言",       "言語",          "언어" },
	/* LKEY_INSTALLED_APP */   { "INSTALLED APP", "已安装",    "インストール済み", "설치됨" },
	/* LKEY_AVAILABLE_APP */   { "AVAILABLE APP", "可安装",    "インストール可能", "설치 가능" },
	/* LKEY_INSTALL_APP */     { "INSTALL APP",  "安装应用",   "アプリをインストール", "앱 설치" },
	/* LKEY_OK */              { "OK",           "确定",       "OK",            "확인" },
	/* LKEY_OK_OPEN */         { "OK: open",     "OK: 打开",   "OK: 開く",       "OK: 열기" },
	/* LKEY_DEL */             { "DEL",          "删除",       "削除",           "삭제" },
	/* LKEY_SPC */             { "SPC",          "空格",       "空白",           "공백" },
	/* LKEY_YES */             { "Yes",          "是",         "はい",           "예" },
	/* LKEY_NO */              { "No",           "否",         "いいえ",         "아니오" },
	/* LKEY_PIN_TOO_SHORT */   { "PIN too short (>=4)", "PIN 太短（至少4位）",
	                             "PINが短すぎます（4桁以上）", "PIN이 너무 짧습니다 (4자 이상)" },
	/* LKEY_PIN_MISMATCH */    { "PIN mismatch", "PIN 不匹配", "PINが一致しません", "PIN이 일치하지 않습니다" },
	/* LKEY_ENTER_WORD */      { "enter word",   "输入单词",   "単語を入力",      "단어 입력" },
	/* LKEY_ENTER_NEXT_WORD */ { "enter next word", "输入下一个单词", "次の単語を入力",
	                             "다음 단어 입력" },
	/* LKEY_WORD_N */          { "WORD %d",       "单词 %d",     "単語 %d",         "단어 %d" },
	/* LKEY_NEED_WORDS_DEV */  { "need 4/12/15/18/21/24 words", "需要 4/12/15/18/21/24 个单词",
	                             "4/12/15/18/21/24語が必要", "4/12/15/18/21/24 단어 필요" },
	/* LKEY_NEED_WORDS */      { "need 12/15/18/21/24 words", "需要 12/15/18/21/24 个单词",
	                             "12/15/18/21/24語が必要", "12/15/18/21/24 단어 필요" },
	/* LKEY_FIDO_SERVING */    { "FIDO serving", "FIDO 服务中", "FIDO 稼働中",    "FIDO 서비스 중" },
	/* LKEY_FIDO_PLUG_BROWSER */ { "plug into a browser", "插入浏览器", "ブラウザに接続してください",
	                              "브라우저에 연결하세요" },
	/* LKEY_REGISTER_NEW_KEY */ { "Register new login key?", "注册新的登录密钥？",
	                              "新しいログインキーを登録しますか？", "새 로그인 키를 등록할까요?" },
	/* LKEY_CONFIRM_LOGIN */   { "Confirm login?", "确认登录？", "ログインを確認しますか？", "로그인할까요?" },
	/* LKEY_REGISTRATION_OK */ { "Registration OK", "注册成功", "登録完了",       "등록 완료" },
	/* LKEY_LOGIN_OK */        { "Login OK",      "登录成功",   "ログイン完了",   "로그인 완료" },
	/* LKEY_DENIED */          { "Denied",        "已拒绝",     "拒否されました", "거부됨" },
	/* LKEY_UNKNOWN_RP */      { "(unknown RP)",  "(未知网站)", "(不明なRP)",     "(알 수 없는 RP)" },
	/* LKEY_FIDO_TASK_ERR */   { "FIDO task error", "FIDO 任务错误", "FIDO タスクエラー", "FIDO 작업 오류" },
	/* LKEY_SESSION_ENDED */   { "session ended", "会话结束",   "セッション終了", "세션 종료" },
	/* LKEY_HOST_LINK_SERVING */ { "Host link serving", "主机连接服务中", "ホスト接続サービス中", "호스트 링크 서비스 중" },
	/* LKEY_WAITING_FRAMES */  { "waiting for frames", "等待数据帧", "フレーム待機中", "프레임 대기 중" },
	/* LKEY_DELETE */          { "DELETE",       "删除",       "削除",          "삭제" },
	/* LKEY_CANCEL */          { "CANCEL",       "取消",       "キャンセル",    "취소" },
	/* LKEY_DELETE_APP */      { "Delete this app?", "删除此应用？", "このアプリを削除しますか？", "이 앱을 삭제할까요?" },
	/* LKEY_BACK */            { "BACK",         "返回",       "戻る",          "뒤로" },
	/* LKEY_ALL_INSTALLED */   { "All apps installed.", "所有应用已安装。", "すべてのアプリがインストール済みです。", "모든 앱이 설치되었습니다." },
	/* LKEY_FIDO_PREINSTALLED */{ "FIDO (preinstalled)", "FIDO (预装)", "FIDO (プリインストール)", "FIDO (사전 설치)" },
	/* LKEY_INSTALL_FIDO */    { "Install FIDO app?", "安装 FIDO 应用？", "FIDOアプリをインストールしますか？", "FIDO 앱을 설치할까요?" },
	/* LKEY_FIDO_INSTALLED_RESTART */ { "FIDO installed. Restart to boot into FIDO.",
	                                  "FIDO 已安装。重启后进入 FIDO。",
	                                  "FIDOがインストールされました。再起動するとFIDOで起動します。",
	                                  "FIDO가 설치되었습니다. 재시작하면 FIDO로 부팅됩니다." },
	/* LKEY_INSTALLED */       { "INSTALLED",    "已安装",     "インストール済み", "설치됨" },
	/* LKEY_DELETED */         { "DELETED",      "已删除",     "削除済み",        "삭제됨" },
	/* LKEY_OK_MANAGE */       { "OK: manage  [+]: install", "OK: 管理  [+]: 安装", "OK: 管理  [+]: インストール", "OK: 관리  [+]: 설치" },
	/* LKEY_PAGE */            { "page %zu/%zu", "第 %zu/%zu 页", "%zu/%zu ページ", "%zu/%zu 페이지" },
	/* LKEY_FIDO_INSTALLED_LIST */ { "FIDO [INSTALLED]", "FIDO [已安装]", "FIDO [インストール済み]", "FIDO [설치됨]" },
	/* LKEY_MOVE_SELECT */     { "< > move cursor, OK select", "< > 移动光标，OK 选择", "< > カーソル移動、OKで選択", "< > 커서 이동, OK 선택" },
	/* LKEY_FIDO_APP */        { "FIDO APP",     "FIDO 应用",  "FIDOアプリ",    "FIDO 앱" },
	/* LKEY_STATE */           { "State: %s",   "状态: %s",   "状態: %s",      "상태: %s" },
	/* LKEY_INIT_WALLET_FIRST */ { "Initialize the wallet first: FIDO keys come from your seed.",
	                              "请先初始化钱包：FIDO 密钥来自你的种子。",
	                              "最初にウォレットを初期化してください：FIDO鍵はシードから生成されます。",
	                              "먼저 지갑을 초기화하세요: FIDO 키는 시드에서 생성됩니다." },
	/* LKEY_INIT_WALLET_FIRST_SHORT */ { "Initialize the wallet first.",
	                              "请先初始化钱包。",
	                              "最初にウォレットを初期化してください。",
	                              "먼저 지갑을 초기화하세요." },
	/* LKEY_DELETE_EXPLAIN */  { "DELETE boots into wallet next power-on and wipes its credentials.",
	                            "删除后下次开机进入钱包，并清除其凭据。",
	                            "削除すると次回起動時にウォレットで起動し、認証情報を消去します。",
	                            "삭제하면 다음 부팅 시 지갑으로 부팅되고 자격 증명이 삭제됩니다." },
	/* LKEY_ACTIVATE_EXPLAIN */{ "ACTIVATE boots into FIDO serving next power-on.",
	                            "激活后下次开机进入 FIDO 服务。",
	                            "有効化すると次回起動時にFIDOサーバーで起動します。",
	                            "활성화하면 다음 부팅 시 FIDO 서비스로 부팅됩니다." },
	/* LKEY_DELETE_FIDO */     { "Delete FIDO app? Credentials are wiped.",
	                            "删除 FIDO 应用？凭据将被清除。",
	                            "FIDOアプリを削除しますか？認証情報は消去されます。",
	                            "FIDO 앱을 삭제할까요? 자격 증명이 삭제됩니다." },
	/* LKEY_FIDO_DELETED */    { "FIDO deleted. Restart to boot into wallet.",
	                            "FIDO 已删除。重启后进入钱包。",
	                            "FIDOが削除されました。再起動するとウォレットで起動します。",
	                            "FIDO가 삭제되었습니다. 재시작하면 지갑으로 부팅됩니다." },
	/* LKEY_ACTIVATE_FIDO */   { "Activate FIDO app?", "激活 FIDO 应用？",
	                            "FIDOアプリを有効化しますか？", "FIDO 앱을 활성화할까요?" },
	/* LKEY_FIDO_ACTIVATED */  { "FIDO activated. Restart to boot into FIDO.",
	                            "FIDO 已激活。重启后进入 FIDO。",
	                            "FIDOが有効化されました。再起動するとFIDOで起動します。",
	                            "FIDO가 활성화되었습니다. 재시작하면 FIDO로 부팅됩니다." },
	/* LKEY_CORE_PREINSTALLED */ { "CORE (preinstalled)", "核心 (预装)", "コア (プリインストール)", "핵심 (사전 설치)" },
	/* LKEY_PIN_SET */         { "PIN SET",      "已设置",     "PIN設定済み",    "PIN 설정됨" },
	/* LKEY_NO_PIN */          { "NO PIN SET",   "未设置",     "PIN未設定",      "PIN 설정 안 됨" },
	/* LKEY_SET_PIN */         { "SET PIN",      "设置PIN",    "PINを設定",      "PIN 설정" },
	/* LKEY_CHANGE_PIN */      { "CHANGE PIN",   "修改PIN",    "PINを変更",      "PIN 변경" },
	/* LKEY_AUTO_LOCK */       { "AUTO-LOCK",    "自动锁定",   "自動ロック",     "자동 잠금" },
	/* LKEY_ENTER_PIN */       { "ENTER PIN",    "输入PIN",    "PINを入力",      "PIN 입력" },
	/* LKEY_CONFIRM_PIN */     { "CONFIRM PIN",  "确认PIN",    "PINを確認",      "PIN 확인" },
	/* LKEY_WRONG_PIN */       { "Wrong PIN.",   "PIN 错误。",  "PINが違います。", "PIN이 잘못되었습니다." },
	/* LKEY_PIN_UPDATED */     { "PIN updated.", "PIN 已更新。", "PINが更新されました。", "PIN이 업데이트되었습니다." },
	/* LKEY_WALLET_LOCKED */   { "Wallet locked", "钱包已锁定", "ウォレットがロックされています", "지갑이 잠겼습니다" },
	/* LKEY_LOCK_NEVER */      { "Never",        "从不",       "なし",           "없음" },
	/* LKEY_LOCK_30S */        { "30s",          "30秒",       "30秒",           "30초" },
	/* LKEY_LOCK_1MIN */       { "1min",         "1分钟",      "1分",            "1분" },
	/* LKEY_LOCK_5MIN */       { "5min",         "5分钟",      "5分",            "5분" },
	/* LKEY_LOCK_10MIN */      { "10min",        "10分钟",     "10分",           "10분" },
	/* LKEY_SET_PIN_PROMPT */  { "Set a PIN to protect the wallet?",
	                            "设置 PIN 以保护钱包？",
	                            "ウォレットを保護するためにPINを設定しますか？",
	                            "지갑을 보호하기 위해 PIN을 설정할까요?" },
	/* LKEY_NOT_INITIALIZED */ { "Not initialized. Run Initialize first.",
	                            "尚未初始化。请先运行初始化。",
	                            "未初期化です。先に初期化を実行してください。",
	                            "초기화되지 않았습니다. 먼저 초기화를 실행하세요." },
	/* LKEY_NO_APP */          { "No app available.", "没有可用应用。", "利用可能なアプリがありません。", "사용 가능한 앱이 없습니다." },
	/* LKEY_CONFIRM */         { "CONFIRM",      "确认",       "確認",           "확인" },
	/* LKEY_UNKNOWN_CALL */    { "UNKNOWN CALL", "未知调用",   "不明な呼び出し", "알 수 없는 호출" },
	/* LKEY_NOT_PARSEABLE */   { "Not parseable. Confirm twice to sign.",
	                            "无法解析。确认两次以签名。",
	                            "解析できません。2回確認して署名します。",
	                            "구문 분석할 수 없습니다. 두 번 확인하여 서명하세요." },
	/* LKEY_TRANSFER */        { "transfer",     "转账",       "送金",           "전송" },
	/* LKEY_TOKEN_TRANSFER */  { "token transfer", "代币转账", "トークン送金",   "토큰 전송" },
	/* LKEY_APPROVE */         { "approve",      "授权",       "承認",           "승인" },
	/* LKEY_CONTRACT */        { "contract",     "合约",       "コントラクト",   "컨트랙트" },
	/* LKEY_SIGN_QUESTION */   { "sign?",        "签名？",     "署名しますか？", "서명할까요?" },
	/* LKEY_UNLOCK_TO_SIGN */  { "Unlock to sign", "解锁后签名", "ロック解除して署名", "잠금 해제 후 서명" },
	/* LKEY_SIGNATURE */       { "Signature (r||s)", "签名 (r||s)", "署名 (r||s)", "서명 (r||s)" },
	/* LKEY_SIGNED_INPUTS */   { "Signed %u input(s), sig[0]:", "已签名 %u 个输入，sig[0]:",
	                            "%u 個の入力を署名、sig[0]:", "%u개 입력 서명됨, sig[0]:" },
	/* LKEY_REJECTED */        { "Rejected by user.", "已被用户拒绝。", "ユーザーに拒否されました。", "사용자가 거부했습니다." },
	/* LKEY_SESSION_LOCKED */  { "Session locked. Re-enter PIN.",
	                            "会话已锁定。请重新输入 PIN。",
	                            "セッションがロックされました。PINを再入力してください。",
	                            "세션이 잠겼습니다. PIN을 다시 입력하세요." },
	/* LKEY_SIGN_UNAVAILABLE */{ "Sign unavailable (rc=%d).", "签名不可用 (rc=%d)。",
	                            "署名できません (rc=%d)。", "서명할 수 없습니다 (rc=%d)." },
	/* LKEY_WRONG_PIN_WIPE */  { "Wrong PIN. Wipe aborted.", "PIN 错误。已中止擦除。",
	                            "PINが違います。消去は中止されました。", "PIN이 잘못되었습니다. 초기화가 중단되었습니다." },
	/* LKEY_TYPE_RESET */      { "TYPE RESET",   "输入 RESET", "RESET と入力",   "RESET 입력" },
	/* LKEY_TYPE_RESET_AGAIN */{ "TYPE RESET AGAIN", "再次输入 RESET", "もう一度 RESET と入力", "RESET 다시 입력" },
	/* LKEY_TYPE_RESET_HINT */ { "Type RESET to confirm wipe.", "输入 RESET 以确认擦除。",
	                            "消去を確認するには RESET と入力してください。", "초기화를 확인하려면 RESET을 입력하세요." },
	/* LKEY_NOT_CONFIRMED */   { "Not confirmed. Wipe aborted.", "未确认。已中止擦除。",
	                            "確認されていません。消去は中止されました。", "확인되지 않았습니다. 초기화가 중단되었습니다." },
	/* LKEY_NOT_CONFIRMED_TWICE */ { "Not confirmed twice. Wipe aborted.", "两次未确认。已中止擦除。",
	                            "2回確認されませんでした。消去は中止されました。", "두 번 확인되지 않았습니다. 초기화가 중단되었습니다." },
	/* LKEY_DEVICE_WIPED */    { "Device wiped. Re-initialize to set a seed.",
	                            "设备已擦除。重新初始化以设置种子。",
	                            "デバイスを消去しました。シードを設定するには再初期化してください。",
	                            "기기가 초기화되었습니다. 시드를 설정하려면 다시 초기화하세요." },
	/* LKEY_WARNING */         { "WARNING",      "警告",       "警告",           "경고" },
	/* LKEY_I_UNDERSTAND */    { "I UNDERSTAND", "我明白",     "理解しました",   "이해했습니다" },
	/* LKEY_SEED_WARNING_1 */  { "Your seed words are your money. They are only generated on and entered into this wallet.",
	                            "你的助记词就是你的钱。它们只在本钱包上生成和输入。",
	                            "シードワードはあなたのお金です。それらはこのウォレットでのみ生成・入力されます。",
	                            "시드 단어는 곧 돈입니다. 이 지갑에서만 생성되고 입력됩니다." },
	/* LKEY_SEED_WARNING_2 */  { "Anyone asking you to reveal them - websites, emails, or apps - is scamming you. Never share them.",
	                            "任何要求你透露助记词的人--网站、邮件或应用--都是在骗你。绝不分享。",
	                            "開示を求める人--ウェブサイト、メール、アプリ--は詐欺です。絶対に共有しないでください。",
	                            "시드 단어를 요구하는 사람(웹사이트, 이메일, 앱)은 사기입니다. 절대 공유하지 마세요." },
	/* LKEY_WORD */            { "Word %d/%d",   "单词 %d/%d", "単語 %d/%d",     "단어 %d/%d" },
	/* LKEY_NEXT */            { "Next",         "下一个",     "次へ",           "다음" },
	/* LKEY_ENABLE_PHRASE */   { "Enable brain phrase?", "启用 BIP39 短语？",
	                            "BIP39 パスフレーズを有効にしますか？", "BIP39 패스프레이즈를 활성화할까요?" },
	/* LKEY_BRAIN_PHRASE */    { "BRAIN PHRASE", "BIP39 短语", "BIP39 パスフレーズ", "BIP39 패스프레이즈" },
	/* LKEY_CONFIRM_BRAIN_PHRASE */ { "CONFIRM BRAIN PHRASE", "确认 BIP39 短语",
	                            "BIP39 パスフレーズを確認", "BIP39 패스프레이즈 확인" },
	/* LKEY_PHRASE_MISMATCH */ { "Passphrase mismatch!", "短语不匹配！",
	                            "パスフレーズが一致しません！", "패스프레이즈가 일치하지 않습니다!" },
	/* LKEY_ENTER_AGAIN */     { "Enter it again.", "请重新输入。", "もう一度入力してください。", "다시 입력하세요." },
	/* LKEY_ALREADY_INIT */    { "Device already initialized. Wipe to re-seed.",
	                            "设备已初始化。擦除后重新设置种子。",
	                            "デバイスは初期化済みです。再シードには消去してください。",
	                            "기기가 이미 초기화되었습니다. 다시 시드하려면 초기화하세요." },
	/* LKEY_SE_STATUS_ERR */   { "SE status error - passphrase gate failed",
	                            "安全模块状态错误 - 口令门失败",
	                            "SE状態エラー - パスフレーズゲートに失敗しました",
	                            "SE 상태 오류 - 패스프레이즈 게이트 실패" },
	/* LKEY_SE_NO_PASSPHRASE */ { "Backend lacks passphrase support",
	                            "后端不支持口令",
	                            "バックエンドはパスフレーズをサポートしていません",
	                            "백엔드가 패스프레이즈를 지원하지 않습니다" },
	/* LKEY_PHRASE_LEN */      { "Phrase length?", "短语长度？", "フレーズ長さ？", "프레이즈 길이?" },
	/* LKEY_WORDS_12 */        { "12 words = 128-bit", "12 单词 = 128 位", "12語 = 128ビット", "12단어 = 128비트" },
	/* LKEY_WORDS_24 */        { "24 words = 256-bit", "24 单词 = 256 位", "24語 = 256ビット", "24단어 = 256비트" },
	/* LKEY_WORDS_4 */         { "4 words (TEST)", "4 单词 (测试)", "4語 (テスト)", "4단어 (테스트)" },
	/* LKEY_ENTROPY */         { "Touch entropy (optional)", "触摸熵 (可选)",
	                            "タッチエントロピー (任意)", "터치 엔트로피 (선택)" },
	/* LKEY_ENTROPY_1 */       { "Press & HOLD the screen anywhere:", "按住屏幕任意位置：",
	                            "画面を長押ししてください：", "화면을 길게 누르세요:" },
	/* LKEY_ENTROPY_2 */       { "your finger's micro-jitter is mixed", "你的手指微抖动将被混入",
	                            "指の微細な揺れが混ぜられます", "손가락의 미세한 떨림이 섞입니다" },
	/* LKEY_ENTROPY_3 */       { "into the new seed.", "到新的种子中。", "新しいシードに混ぜられます。", "새 시드에 섞입니다." },
	/* LKEY_ENTROPY_4 */       { "Holding starts a 3-2-1-0 count,", "按住会开始 3-2-1-0 倒计时，",
	                            "長押しで 3-2-1-0 カウントが始まり、", "길게 누르면 3-2-1-0 카운트가 시작되고," },
	/* LKEY_ENTROPY_5 */       { "then the seed generates by itself.", "然后种子会自动生成。",
	                            "その後シードが自動生成されます。", "그러면 시드가 자동으로 생성됩니다." },
	/* LKEY_SKIP */            { "SKIP",         "跳过",       "スキップ",       "건너뛰기" },
	/* LKEY_KEEP_HOLDING */    { "Keep holding... %d", "请继续按住... %d", "押し続けてください... %d", "계속 누르세요... %d" },
	/* LKEY_SEED_FAILED */     { "seed gen failed", "种子生成失败", "シード生成に失敗", "시드 생성 실패" },
	/* LKEY_RELEASE */         { "OK, release now", "好，现在松开", "OK、離してください", "좋아요, 이제 놓으세요" },
	/* LKEY_VERIFY */          { "Verify: re-enter the phrase", "验证：重新输入短语",
	                            "確認：フレーズを再入力", "확인: 프레이즈 다시 입력" },
	/* LKEY_CONFIRM_PHRASE */  { "CONFIRM PHRASE", "确认短语", "フレーズを確認", "프레이즈 확인" },
	/* LKEY_PHRASE_MISMATCH_2 */ { "Phrase does NOT match.", "短语不匹配。",
	                            "フレーズが一致しません。", "프레이즈가 일치하지 않습니다." },
	/* LKEY_REVIEW */          { "Review words and retry.", "检查单词后重试。",
	                            "単語を確認して再試行してください。", "단어를 확인하고 다시 시도하세요." },
	/* LKEY_RETRY */           { "RETRY",        "重试",       "再試行",         "다시 시도" },
	/* LKEY_ABORT */           { "ABORT",        "中止",       "中止",           "중단" },
	/* LKEY_CANCELLED */       { "cancelled",    "已取消",     "キャンセルしました", "취소됨" },
	/* LKEY_INIT_OK */         { "Initialized OK. Seed stored.", "初始化成功。种子已存储。",
	                            "初期化完了。シードを保存しました。", "초기화 완료. 시드가 저장되었습니다." },
	/* LKEY_STORE_FAILED */    { "store seed failed", "存储种子失败", "シード保存に失敗", "시드 저장 실패" },
	/* LKEY_ALREADY_INIT_2 */  { "Already initialized. Factory-reset first.",
	                            "已初始化。请先恢复出厂设置。",
	                            "初期化済みです。先に工場出荷時リセットしてください。",
	                            "이미 초기화되었습니다. 먼저 공장 초기화하세요." },
	/* LKEY_RECOVER_PHRASE */  { "RECOVER PHRASE", "恢复短语", "フレーズを復元", "프레이즈 복구" },
	/* LKEY_INVALID_MNEMONIC */{ "Invalid mnemonic.", "无效助记词。", "無効なニーモニックです。", "잘못된 니모닉입니다." },
	/* LKEY_RECOVERED */       { "Recovered. Seed stored.", "恢复成功。种子已存储。",
	                            "復元完了。シードを保存しました。", "복구 완료. 시드가 저장되었습니다." },
	/* LKEY_CHIP */            { "Chip %s",      "芯片 %s",    "チップ %s",      "칩 %s" },
	/* LKEY_FLASH_MB */        { "Flash %d MB",  "闪存 %d MB", "フラッシュ %d MB", "플래시 %d MB" },
	/* LKEY_FLASH_UNKNOWN */   { "Flash unknown", "闪存未知",  "フラッシュ不明",  "플래시 알 수 없음" },
	/* LKEY_CORES */           { "Cores %d",     "核心 %d",    "コア %d",        "코어 %d" },
	/* LKEY_FIRMWARE */        { "Firmware",     "固件",       "ファームウェア", "펌웨어" },
	/* LKEY_BUILD */           { "Build %s",     "构建 %s",    "ビルド %s",      "빌드 %s" },
};

static const char *const s_lang_names[LANG_COUNT] = {
	"ENGLISH", "中文", "日本語", "한국어",
};

_Static_assert(LKEY_COUNT == (sizeof s_labels / sizeof s_labels[0]),
               "lang.h and lang.c key tables out of sync");

/* ---------------------------------------------------------------- */

lang_id_t os_lang_get(void)
{
	return s_lang;
}

void os_lang_set(lang_id_t id)
{
	if (id < 0 || id >= LANG_COUNT)
		return;
	s_lang = id;
	nvs_handle_t h;
	if (nvs_open(LANG_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
		nvs_set_u8(h, LANG_NVS_KEY, (uint8_t)id);
		nvs_commit(h);
		nvs_close(h);
	}
}

void os_lang_load(void)
{
	nvs_handle_t h;
	if (nvs_open(LANG_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
		uint8_t v = 0;
		if (nvs_get_u8(h, LANG_NVS_KEY, &v) == ESP_OK && v < LANG_COUNT)
			s_lang = (lang_id_t)v;
		nvs_close(h);
	}
}

const char *os_lang_str(lang_key_t key)
{
	if (key < 0 || key >= LKEY_COUNT)
		return "";
	return s_labels[key][s_lang];
}

const char *os_lang_name(lang_id_t id)
{
	if (id < 0 || id >= LANG_COUNT)
		return "";
	return s_lang_names[id];
}
