import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { AuthProvider, RequireRole } from "./auth";
import { Layout } from "./components";
import { LoginPage, RegisterPage } from "./pages/Auth";
import { HomePage } from "./pages/Citizen";

vi.mock("./api", async (original) => {
  const actual = await original<typeof import("./api")>();
  return { ...actual, refreshSession: vi.fn(), login: vi.fn(), logout: vi.fn(), register: vi.fn(),
    petitions: { create: vi.fn(), mine: vi.fn(async () => []), get: vi.fn() } };
});

const citizen = { id: 1, username: "kim", display_name: "김시민", role: "citizen" as const };
const staffUser = { id: 2, username: "lee", display_name: "이담당", role: "staff" as const };

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<HomePage />} />
            <Route path="login" element={<LoginPage />} />
            <Route path="register" element={<RegisterPage />} />
            <Route path="staff" element={<RequireRole roles={["staff", "admin"]}><p>담당자 화면</p></RequireRole>} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(api.refreshSession).mockReset().mockResolvedValue(null);
  vi.mocked(api.login).mockReset();
  vi.mocked(api.register).mockReset();
});

describe("로그인 화면", () => {
  it("아이디와 비밀번호가 비어 있으면 제출 버튼이 비활성이다", async () => {
    renderAt("/login");
    expect(await screen.findByRole("button", { name: "로그인" })).toBeDisabled();
  });

  it("로그인 실패 메시지를 알림 영역에 보여 준다", async () => {
    vi.mocked(api.login).mockRejectedValue(new api.ApiError(401, "INVALID_CREDENTIALS", "아이디·비밀번호를 확인해 주세요."));
    renderAt("/login");
    await userEvent.type(await screen.findByLabelText("아이디"), "kim");
    await userEvent.type(screen.getByLabelText("비밀번호"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "로그인" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("아이디·비밀번호를 확인해 주세요.");
  });

  it("성공하면 역할에 맞는 화면으로 이동한다", async () => {
    vi.mocked(api.login).mockResolvedValue(staffUser);
    renderAt("/login");
    await userEvent.type(await screen.findByLabelText("아이디"), "lee");
    await userEvent.type(screen.getByLabelText("비밀번호"), "long-enough-pw");
    await userEvent.click(screen.getByRole("button", { name: "로그인" }));
    expect(await screen.findByText("담당자 화면")).toBeInTheDocument();
    expect(api.login).toHaveBeenCalledWith("lee", "long-enough-pw");
  });

  it("제출 중에는 버튼이 잠겨 중복 전송을 막는다", async () => {
    let finish: (u: typeof staffUser) => void = () => {};
    vi.mocked(api.login).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    renderAt("/login");
    await userEvent.type(await screen.findByLabelText("아이디"), "lee");
    await userEvent.type(screen.getByLabelText("비밀번호"), "long-enough-pw");
    await userEvent.click(screen.getByRole("button", { name: "로그인" }));
    expect(await screen.findByRole("button", { name: "확인 중…" })).toBeDisabled();
    expect(api.login).toHaveBeenCalledTimes(1);
    finish(staffUser);
  });
});

describe("가입 화면", () => {
  it("짧은 비밀번호는 서버에 보내지 않고 안내한다", async () => {
    renderAt("/register");
    await userEvent.type(await screen.findByLabelText(/아이디/), "newuser");
    await userEvent.type(screen.getByLabelText(/표시 이름/), "새사용자");
    await userEvent.type(screen.getByLabelText(/^비밀번호 \(/), "short");
    await userEvent.type(screen.getByLabelText("비밀번호 확인"), "short");
    await userEvent.click(screen.getByRole("button", { name: "가입" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("10자 이상");
    expect(api.register).not.toHaveBeenCalled();
  });

  it("비밀번호 확인이 다르면 안내한다", async () => {
    renderAt("/register");
    await userEvent.type(await screen.findByLabelText(/아이디/), "newuser");
    await userEvent.type(screen.getByLabelText(/표시 이름/), "새사용자");
    await userEvent.type(screen.getByLabelText(/^비밀번호 \(/), "long-enough-pw");
    await userEvent.type(screen.getByLabelText("비밀번호 확인"), "different-long-pw");
    await userEvent.click(screen.getByRole("button", { name: "가입" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("일치하지 않습니다");
  });

  it("가입에 성공하면 로그인 화면으로 보내고 안내한다", async () => {
    vi.mocked(api.register).mockResolvedValue(citizen);
    renderAt("/register");
    await userEvent.type(await screen.findByLabelText(/아이디/), "newuser");
    await userEvent.type(screen.getByLabelText(/표시 이름/), "새사용자");
    await userEvent.type(screen.getByLabelText(/^비밀번호 \(/), "long-enough-pw");
    await userEvent.type(screen.getByLabelText("비밀번호 확인"), "long-enough-pw");
    await userEvent.click(screen.getByRole("button", { name: "가입" }));
    expect(await screen.findByText("가입이 완료되었습니다. 로그인해 주세요.")).toBeInTheDocument();
  });
});

describe("권한 처리", () => {
  it("로그인하지 않으면 담당자 화면에서 로그인 화면으로 보낸다", async () => {
    renderAt("/staff");
    expect(await screen.findByRole("heading", { name: "로그인" })).toBeInTheDocument();
  });

  it("시민이 담당자 화면에 들어가면 권한 없음 안내를 보여 준다", async () => {
    vi.mocked(api.refreshSession).mockResolvedValue(citizen);
    renderAt("/staff");
    expect(await screen.findByRole("alert")).toHaveTextContent("권한이 없습니다");
  });

  it("상단 메뉴는 역할에 따라 다르다", async () => {
    vi.mocked(api.refreshSession).mockResolvedValue(staffUser);
    renderAt("/");
    expect(await screen.findByRole("link", { name: "민원 처리" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "계정 관리" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "내 민원" })).not.toBeInTheDocument();
  });
});

describe("홈", () => {
  it("방문자에게는 로그인·가입 안내를 보여 준다", async () => {
    renderAt("/");
    expect(await screen.findByRole("heading", { name: "누리시청 민원 포털" })).toBeInTheDocument();
  });

  it("시민은 내 민원 목록을 불러온다", async () => {
    vi.mocked(api.refreshSession).mockResolvedValue(citizen);
    vi.mocked(api.petitions.mine).mockResolvedValue([{
      id: 7, owner_id: 1, category: "road", title: "가로등 고장", body: "꺼졌습니다", status: "received",
      assignee_id: null, version: 1, created_at: "2026-11-10T01:00:00", updated_at: "2026-11-10T01:00:00",
    }]);
    renderAt("/");
    expect(await screen.findByRole("link", { name: "가로등 고장" })).toHaveAttribute("href", "/petitions/7");
    expect(within(screen.getByRole("list")).getByText("접수")).toBeInTheDocument();  // 목록의 상태 배지
  });
});
