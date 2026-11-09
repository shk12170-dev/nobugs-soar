import { Route, Routes } from "react-router-dom";
import { RequireRole } from "./auth";
import { Layout } from "./components";
import { AdminUsersPage } from "./pages/Admin";
import { LoginPage, RegisterPage } from "./pages/Auth";
import { HomePage, PetitionDetailPage } from "./pages/Citizen";
import { StaffBoardPage, StaffPetitionPage } from "./pages/Staff";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<HomePage />} />
        <Route path="login" element={<LoginPage />} />
        <Route path="register" element={<RegisterPage />} />
        <Route path="petitions/:id" element={<RequireRole roles={["citizen", "staff", "admin"]}><PetitionDetailPage /></RequireRole>} />
        <Route path="staff" element={<RequireRole roles={["staff", "admin"]}><StaffBoardPage /></RequireRole>} />
        <Route path="staff/petitions/:id" element={<RequireRole roles={["staff", "admin"]}><StaffPetitionPage /></RequireRole>} />
        <Route path="admin" element={<RequireRole roles={["admin"]}><AdminUsersPage /></RequireRole>} />
        <Route path="*" element={<p role="alert" className="notice error">페이지를 찾을 수 없습니다.</p>} />
      </Route>
    </Routes>
  );
}
