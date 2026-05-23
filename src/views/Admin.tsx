export function Admin() {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-xl font-bold text-[#e1e4e8]">Admin</h2>
        <p className="text-sm text-[#8b949e]">Platform configuration &amp; user management</p>
      </div>

      <div className="rounded-lg border border-dashed border-[#30363d] bg-[#161b22] p-8 text-center">
        <div className="text-4xl mb-3">⚙️</div>
        <h3 className="text-lg font-medium text-[#e1e4e8] mb-2">Admin Panel Coming in M4</h3>
        <p className="text-sm text-[#8b949e] max-w-md mx-auto">
          Role-based access control, user management, tenant settings, API keys, and audit logs
          will be built in Milestone 4.
        </p>
      </div>
    </div>
  );
}
