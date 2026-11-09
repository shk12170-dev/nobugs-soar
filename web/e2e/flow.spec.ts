import { expect, test, type Page } from "@playwright/test";

// scripts/e2e_server.py 가 만들어 두는 시험 전용 계정(합성 값)
const STAFF = { username: "staff_e2e", password: "E2e-Staff-Passw0rd-1" };
const ADMIN = { username: "admin_e2e", password: "E2e-Admin-Passw0rd-1" };
const unique = Date.now().toString(36);
const CITIZEN = { username: `citizen_${unique}`, name: "시험 시민", password: "E2e-Citizen-Passw0rd-1" };

async function login(page: Page, username: string, password: string) {
  await page.goto("/login");
  await page.getByLabel("아이디").fill(username);
  await page.getByLabel("비밀번호").fill(password);
  await page.getByRole("button", { name: "로그인" }).click();
}

async function logout(page: Page) {
  await page.getByRole("button", { name: /로그아웃/ }).click();
  await expect(page.getByRole("heading", { name: "로그인" })).toBeVisible();
}

test.describe.serial("민원 접수부터 처리·확인까지", () => {
  test("시민이 가입하고 로그인해 민원을 접수한다", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "누리시청 민원 포털" })).toBeVisible();
    await page.getByRole("link", { name: "가입", exact: true }).first().click();
    await page.getByLabel(/아이디/).fill(CITIZEN.username);
    await page.getByLabel(/표시 이름/).fill(CITIZEN.name);
    await page.getByLabel(/^비밀번호 \(/).fill(CITIZEN.password);
    await page.getByLabel("비밀번호 확인").fill(CITIZEN.password);
    await page.getByRole("button", { name: "가입" }).click();
    await expect(page.getByText("가입이 완료되었습니다")).toBeVisible();

    await page.getByLabel("아이디").fill(CITIZEN.username);
    await page.getByLabel("비밀번호").fill(CITIZEN.password);
    await page.getByRole("button", { name: "로그인" }).click();
    await expect(page.getByRole("heading", { name: "내 민원" })).toBeVisible();

    await page.getByLabel("제목 (2~100자)").fill("가로등 고장 신고");
    await page.getByLabel("내용 (5~2000자)").fill("OO로 12번 앞 가로등이 며칠째 꺼져 있습니다.");
    await page.getByRole("button", { name: "접수", exact: true }).click();
    await expect(page.getByText("민원이 접수되었습니다.")).toBeVisible();
    await expect(page.getByRole("link", { name: "가로등 고장 신고" })).toBeVisible();
    await logout(page);
  });

  test("담당자가 배정·처리하고 답변을 남긴다", async ({ page }) => {
    await login(page, STAFF.username, STAFF.password);
    await expect(page.getByRole("heading", { name: "민원 처리" })).toBeVisible();
    await page.getByRole("link", { name: "가로등 고장 신고" }).click();

    await page.getByRole("button", { name: "내가 맡기" }).click();
    await expect(page.getByRole("button", { name: "처리 시작" })).toBeVisible();
    await page.getByRole("button", { name: "처리 시작" }).click();
    await page.getByLabel("시민에게 보낼 답변").fill("현장을 확인했고 내일 수리하겠습니다.");
    await page.getByRole("button", { name: "답변 등록" }).click();
    await expect(page.getByText("현장을 확인했고 내일 수리하겠습니다.")).toBeVisible();
    await page.getByRole("button", { name: "완료 처리" }).click();
    await expect(page.getByText("완료된 민원입니다.")).toBeVisible();
    await logout(page);
  });

  test("시민이 처리 결과와 답변을 확인한다", async ({ page }) => {
    await login(page, CITIZEN.username, CITIZEN.password);
    await page.getByRole("link", { name: "가로등 고장 신고" }).click();
    await expect(page.getByText("현장을 확인했고 내일 수리하겠습니다.")).toBeVisible();
    await expect(page.getByRole("heading", { name: /가로등 고장 신고/ }).getByText("완료")).toBeVisible();
    // 처리 이력에 접수 → 배정 → 처리 시작 → 답변 → 완료가 남아 있다
    const timeline = page.getByRole("list").filter({ hasText: "처리 완료" });
    await expect(timeline).toContainText("접수");
    await expect(timeline).toContainText("담당자 배정");
  });
});

test.describe("권한과 보안", () => {
  test("시민은 담당자·관리자 화면에 들어갈 수 없다", async ({ page }) => {
    const user = { username: `citizen2_${unique}`, password: "E2e-Citizen-Passw0rd-2" };
    await page.goto("/register");
    await page.getByLabel(/아이디/).fill(user.username);
    await page.getByLabel(/표시 이름/).fill("권한 시험");
    await page.getByLabel(/^비밀번호 \(/).fill(user.password);
    await page.getByLabel("비밀번호 확인").fill(user.password);
    await page.getByRole("button", { name: "가입" }).click();
    await login(page, user.username, user.password);
    await expect(page.getByRole("heading", { name: "내 민원" })).toBeVisible();
    for (const path of ["/staff", "/admin"]) {
      await page.goto(path);
      await expect(page.getByRole("alert")).toContainText("권한이 없습니다");
    }
  });

  test("로그인하지 않으면 업무 화면에서 로그인으로 이동한다", async ({ page }) => {
    await page.goto("/staff");
    await expect(page.getByRole("heading", { name: "로그인" })).toBeVisible();
  });

  test("관리자가 계정을 잠그면 그 사용자는 로그인할 수 없다", async ({ page, browser }) => {
    const target = { username: `locktarget_${unique}`, password: "E2e-Citizen-Passw0rd-3" };
    await page.goto("/register");
    await page.getByLabel(/아이디/).fill(target.username);
    await page.getByLabel(/표시 이름/).fill("잠금 대상");
    await page.getByLabel(/^비밀번호 \(/).fill(target.password);
    await page.getByLabel("비밀번호 확인").fill(target.password);
    await page.getByRole("button", { name: "가입" }).click();

    await login(page, ADMIN.username, ADMIN.password);
    await page.getByRole("link", { name: "계정 관리" }).click();
    await page.getByLabel("검색").fill(target.username);
    const row = page.getByRole("row", { name: new RegExp(target.username) });
    await row.getByRole("button", { name: "잠금", exact: true }).click();
    await expect(page.getByText("계정을 잠그고 세션을 모두 끊었습니다")).toBeVisible();

    const other = await browser.newContext();
    const victim = await other.newPage();
    await login(victim, target.username, target.password);
    await expect(victim.getByRole("alert")).toContainText("확인해 주세요");
    await other.close();
  });

  test("응답에 보안 헤더가 있고 존재하지 않는 경로는 404다", async ({ page, request }) => {
    const response = await page.goto("/login");
    expect(response?.headers()["content-security-policy"]).toContain("default-src 'self'");
    expect(response?.headers()["x-frame-options"]).toBe("DENY");
    expect((await request.get("/wp-admin.php")).status()).toBe(404);
  });
});
