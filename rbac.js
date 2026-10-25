/**
 * Black Rock Enterprise IAM - Role-Based Access Control (RBAC) Engine
 * Seamless Role-Based Dynamic Access: Dynamically adjusts sidebar menus,
 * dashboard metrics, and action capabilities based on the active role,
 * without crude error popups or broken navigation.
 */

(function (window) {
    'use strict';

    // Defined module permissions per role
    const ROLES = {
        GLOBAL_ADMIN: {
            title: "Global Administrator",
            icon: "",
            badge: "GLOBAL_ADMIN (Full Access)",
            level: 100,
            allowedPages: [
                "index.html",
                "user-role.html",
                "roles.html",
                "permissions.html",
                "access-management.html",
                "audit-trail.html",
                "api-architecture.html",
                "create-user.html",
                "createuser.html",
                "login.html"
            ],
            canApproveRequests: true,
            canModifyUsers: true,
            canCreateRoles: true,
            canElevateFullAccess: true
        },
        ADMIN: {
            title: "Administrator",
            icon: "",
            badge: "ADMIN",
            level: 80,
            allowedPages: [
                "index.html",
                "user-role.html",
                "roles.html",
                "permissions.html",
                "access-management.html",
                "audit-trail.html",
                "create-user.html",
                "createuser.html",
                "login.html"
            ],
            canApproveRequests: true,
            canModifyUsers: true,
            canCreateRoles: true,
            canElevateFullAccess: false
        },
        MANAGER: {
            title: "Team Manager",
            icon: "",
            badge: "MANAGER",
            level: 60,
            allowedPages: [
                "index.html",
                "user-role.html",
                "roles.html",
                "access-management.html",
                "login.html"
            ],
            canApproveRequests: true,
            canModifyUsers: false,
            canCreateRoles: false,
            canElevateFullAccess: false
        },
        DEVELOPER: {
            title: "Developer / Engineer",
            icon: "",
            badge: "DEVELOPER",
            level: 40,
            allowedPages: [
                "index.html",
                "user-role.html",
                "permissions.html",
                "access-management.html",
                "api-architecture.html",
                "login.html"
            ],
            canApproveRequests: false,
            canModifyUsers: false,
            canCreateRoles: false,
            canElevateFullAccess: false
        },
        SECURITY_ANALYST: {
            title: "Security Analyst / Auditor",
            icon: "",
            badge: "SECURITY ANALYST",
            level: 50,
            allowedPages: [
                "index.html",
                "user-role.html",
                "permissions.html",
                "audit-trail.html",
                "login.html"
            ],
            canApproveRequests: false,
            canModifyUsers: false,
            canCreateRoles: false,
            canElevateFullAccess: false
        },
        USER: {
            title: "Standard Employee",
            icon: "",
            badge: "USER",
            level: 10,
            allowedPages: [
                "index.html",
                "user-role.html",
                "access-management.html",
                "login.html"
            ],
            canApproveRequests: false,
            canModifyUsers: false,
            canCreateRoles: false,
            canElevateFullAccess: false
        }
    };

    const RBAC = {
        ROLES,

        
        checkAuthentication() {
            const publicPages = ["login.html", "signup.html", "forget-password.html", "reset-password.html"];
            const currentPage = this.getCurrentPage();
            if (!publicPages.includes(currentPage)) {
                if (sessionStorage.getItem("honAuthenticated") !== "true") {
                    console.log("[RBAC] Unauthenticated user. Redirecting to login.html...");
                    window.location.href = "login.html";
                    return false;
                }
            }
            return true;
        },

        getCurrentRole() {
            let role = (sessionStorage.getItem("honUserRole") || "").toUpperCase().trim();
            if (!role) {
                role = "GLOBAL_ADMIN";
                sessionStorage.setItem("honUserRole", role);
            }
            if (role === "SECURITY_OFFICER" || role === "AUDITOR") {
                role = "SECURITY_ANALYST";
            }
            return ROLES[role] ? role : "GLOBAL_ADMIN";
        },

        getCurrentUser() {
            return sessionStorage.getItem("honUsername") || "Naveen";
        },

        getRoleConfig(roleName) {
            const role = (roleName || this.getCurrentRole()).toUpperCase().trim();
            return ROLES[role] || ROLES.GLOBAL_ADMIN;
        },

        getCurrentPage() {
            if (typeof window !== "undefined" && window.location && window.location.pathname) {
                return (window.location.pathname.split('/').pop() || "index.html").toLowerCase();
            }
            return "index.html";
        },

        switchRole(newRole, reload = true) {
            const targetRole = (newRole || "GLOBAL_ADMIN").toUpperCase().trim();
            if (!ROLES[targetRole]) {
                console.error("Unknown role:", newRole);
                return;
            }

            const prevRole = this.getCurrentRole();
            const user = this.getCurrentUser();

            sessionStorage.setItem("honAuthenticated", "true");
            sessionStorage.setItem("honUserRole", targetRole);

            if (window.TwilioMFA && typeof window.TwilioMFA.logAudit === "function") {
                window.TwilioMFA.logAudit(
                    user,
                    `Role Switched: ${prevRole} → ${targetRole}`,
                    "RBAC Engine",
                    "SUCCESS"
                );
            }

            console.log(`[RBAC] Role switched to ${targetRole}`);

            if (reload) {
                // If on a page not available for the new role, smoothly route to index.html
                const currentPage = this.getCurrentPage();
                const newRoleConfig = this.getRoleConfig(targetRole);
                const allowed = (newRoleConfig.allowedPages || []).map(p => p.toLowerCase());
                if (!allowed.includes(currentPage)) {
                    window.location.href = "index.html";
                } else {
                    window.location.reload();
                }
            } else {
                this.applyRBACToUI();
            }
        },

        injectStyles() {
            if (document.getElementById("rbac-dynamic-styles")) return;
            const style = document.createElement("style");
            style.id = "rbac-dynamic-styles";
            style.textContent = `
                /* Role Switcher in Topbar */
                .rbac-topbar-control {
                    display: inline-flex;
                    align-items: center;
                    gap: 10px;
                    padding: 6px 14px;
                    border-radius: 12px;
                    background: #eee3d2 !important;
                    border: 1px solid #dfd2bf !important;
                    box-shadow: 0 2px 8px rgba(73, 54, 35, 0.06) !important;
                }
                .rbac-control-label {
                    font-size: 11px;
                    font-weight: 700;
                    letter-spacing: 0.5px;
                    text-transform: uppercase;
                    color: #795039 !important;
                    white-space: nowrap;
                    display: flex;
                    align-items: center;
                    gap: 4px;
                }
                .rbac-role-select {
                    background: #fffdf8 !important;
                    color: #30271f !important;
                    border: 1px solid #dfd2bf !important;
                    padding: 5px 10px;
                    border-radius: 8px;
                    font-size: 13px;
                    font-weight: 700;
                    outline: none;
                    cursor: pointer;
                    transition: all 0.2s ease;
                }
                .rbac-role-select:focus,
                .rbac-role-select:hover {
                    border-color: #795039 !important;
                    box-shadow: 0 0 8px rgba(121, 80, 57, 0.2) !important;
                }

                /* Smooth transition for navigation */
                .menu a {
                    transition: all 0.25s ease;
                }
            `;
            document.head.appendChild(style);
        },

        mountRoleSwitcher() {
            const currentRole = this.getCurrentRole();
            const topbarActions = document.querySelector(".topbar-actions") ||
                                  document.querySelector(".top-buttons") ||
                                  document.querySelector(".top-actions") ||
                                  document.querySelector(".topbar") ||
                                  document.querySelector(".header") ||
                                  document.querySelector("header");

            if (!topbarActions) return;

            const existing = document.getElementById("rbacTopbarControl");
            if (existing) existing.remove();

            const control = document.createElement("div");
            control.id = "rbacTopbarControl";
            control.className = "rbac-topbar-control";
            control.innerHTML = `
                <span class="rbac-control-label">
                     Role:
                </span>
                <select class="rbac-role-select" id="rbacGlobalRoleSelect" onchange="RBAC.switchRole(this.value)">
                    <option value="GLOBAL_ADMIN" ${currentRole === 'GLOBAL_ADMIN' ? 'selected' : ''}>GLOBAL_ADMIN (Full Access)</option>
                    <option value="ADMIN" ${currentRole === 'ADMIN' ? 'selected' : ''}>ADMIN</option>
                    <option value="MANAGER" ${currentRole === 'MANAGER' ? 'selected' : ''}>MANAGER</option>
                    <option value="DEVELOPER" ${currentRole === 'DEVELOPER' ? 'selected' : ''}>DEVELOPER</option>
                    <option value="SECURITY_ANALYST" ${currentRole === 'SECURITY_ANALYST' ? 'selected' : ''}>SECURITY ANALYST</option>
                    <option value="USER" ${currentRole === 'USER' ? 'selected' : ''}>USER</option>
                </select>
            `;

            const profile = topbarActions.querySelector(".admin-profile") || topbarActions.querySelector(".user-profile");
            if (profile) {
                topbarActions.insertBefore(control, profile);
            } else {
                topbarActions.appendChild(control);
            }
        },

        applySidebarMenuVisibility() {
            // Dynamically show or hide menu items based on active role
            const currentRole = this.getCurrentRole();
            const config = this.getRoleConfig(currentRole);
            const allowed = (config.allowedPages || []).map(p => p.toLowerCase());

            const links = document.querySelectorAll(".menu a, .nav, aside a, .sidebar a");
            links.forEach(link => {
                const href = link.getAttribute("href");
                if (!href || href.startsWith("#") || href.includes("login.html") || href.includes("javascript")) return;

                const page = href.split('/').pop().toLowerCase();
                if (!allowed.includes(page)) {
                    // Hide gracefully
                    link.style.display = "none";
                } else {
                    link.style.display = "flex";
                }
            });
        },

        updateProfileCard() {
            const currentRole = this.getCurrentRole();
            const roleConfig = this.getRoleConfig(currentRole);
            const user = this.getCurrentUser();

            // Update role text across all pages
            document.querySelectorAll("#currentUserRole, .admin-info small, .profile-text small").forEach(el => {
                el.textContent = roleConfig.badge;
            });

            // Update user name across all pages
            document.querySelectorAll("#currentUserName, .admin-info b, .profile-text strong").forEach(el => {
                el.textContent = user;
            });

            // Update avatar letter/icon across all pages
            document.querySelectorAll("#currentAvatar, .admin-avatar, .avatar").forEach(el => {
                const initial = (user && user.trim().length > 0) ? user.trim()[0].toUpperCase() : "A";
                el.textContent = initial;
            });
        },

        bindTopButtons() {
            // Ensure all topbar action buttons across pages have working event listeners
            document.querySelectorAll(".top-button, button").forEach(btn => {
                const text = (btn.textContent || "").trim();
                if (text.includes("API Inspector") && !btn.getAttribute("onclick")) {
                    btn.onclick = () => window.location.href = "api-architecture.html";
                    btn.style.cursor = "pointer";
                }
                if (text.includes("Switch Role") && !btn.getAttribute("onclick")) {
                    btn.onclick = () => window.switchSessionRole();
                    btn.style.cursor = "pointer";
                }
            });
        },

        applyRBACToUI() {
            this.mountRoleSwitcher();
            this.updateProfileCard();
            this.applySidebarMenuVisibility();
            this.bindTopButtons();
        },

        init() {
            if (!this.checkAuthentication()) return;
            this.injectStyles();
            this.applyRBACToUI();
        }
    };

    window.switchSessionRole = function() {
        const roles = ["GLOBAL_ADMIN", "ADMIN", "MANAGER", "DEVELOPER", "SECURITY_ANALYST", "USER"];
        const current = (window.RBAC && typeof window.RBAC.getCurrentRole === 'function')
            ? window.RBAC.getCurrentRole()
            : (sessionStorage.getItem("honUserRole") || "GLOBAL_ADMIN");
        const nextIdx = (roles.indexOf(current) + 1) % roles.length;
        if (window.RBAC && typeof window.RBAC.switchRole === 'function') {
            window.RBAC.switchRole(roles[nextIdx]);
        } else {
            sessionStorage.setItem("honUserRole", roles[nextIdx]);
            sessionStorage.setItem("honAuthenticated", "true");
            window.location.reload();
        }
    };

    window.openApiInspector = function() {
        window.location.href = "api-architecture.html";
    };

    window.endDemoSession = function() {
        sessionStorage.removeItem("honAuthenticated");
        sessionStorage.removeItem("honUsername");
        sessionStorage.removeItem("honUserRole");
    };

    // Auto-initialize when DOM is ready
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => RBAC.init());
    } else {
        RBAC.init();
    }

    window.RBAC = RBAC;

})(window);
