"use strict";

// Service presets for the "New key" wizard. Each variant knows how to build
// the upstream, where the user creates the real token, how to test it and
// which access rules to grant. Grants are deliberately narrow defaults; the
// wizard shows them and lets the user edit them before the key is created.

const ATLASSIAN_TOKENS = "https://id.atlassian.com/manage-profile/security/api-tokens";

const siteField = (suffix, placeholder) => ({ id: "site", label: "Site", prefix: "https://", suffix, placeholder, kind: "site" });
const urlField = (placeholder, label = "Server URL") => ({ id: "url", label, placeholder, kind: "url" });
const emailField = (label) => ({ id: "email", label, placeholder: "you@example.com", kind: "email",
  hint: "Used with the token as basic auth. Only stored in the gateway config." });

const read = (...paths) => ({ upstream: "", methods: ["GET"], paths });
const rw = (methods, ...paths) => ({ upstream: "", methods, paths });

const PRESETS = [
  {
    id: "jira", name: "Jira", mark: "J", color: "#2f6fd6", env: "JIRA", blurb: "Issues, boards and comments",
    variants: [
      {
        id: "cloud", label: "Jira Cloud", fields: [siteField(".atlassian.net", "your-team"), emailField("Atlassian account e-mail")],
        base: (v) => `https://${v.site}.atlassian.net`, auth: { type: "basic" }, username: (v) => v.email,
        headers: { "X-Atlassian-Token": "no-check" }, test: "/rest/api/3/myself",
        token: () => ATLASSIAN_TOKENS, tokenHelp: () => "Create API token → name it “Hootway” → copy it. The token acts with your Jira permissions.",
        levels: {
          read: [read("/rest/api/3/**", "/rest/agile/1.0/**"), rw(["POST"], "/rest/api/3/search/jql", "/rest/api/3/search/approximate-count")],
          write: [read("/rest/api/3/**", "/rest/agile/1.0/**"), rw(["POST"], "/rest/api/3/search/jql", "/rest/api/3/search/approximate-count"),
            rw(["POST", "PUT"], "/rest/api/3/issue/**")],
        },
      },
      {
        id: "dc", label: "Self-hosted (Data Center)", fields: [urlField("https://jira.example.com")],
        base: (v) => v.url, auth: { type: "bearer" }, test: "/rest/api/2/myself",
        headers: { "X-Atlassian-Token": "no-check" },
        token: (v) => `${v.url}/secure/ViewProfile.jspa?selectedTab=com.atlassian.pats.pats-plugin:jira-user-personal-access-tokens`,
        tokenHelp: () => "Create token → name it “Hootway”, set an expiry → copy it. Needs Jira 8.14 or newer.",
        levels: {
          read: [read("/rest/api/2/**", "/rest/agile/1.0/**"), rw(["POST"], "/rest/api/2/search")],
          write: [read("/rest/api/2/**", "/rest/agile/1.0/**"), rw(["POST"], "/rest/api/2/search"), rw(["POST", "PUT"], "/rest/api/2/issue/**")],
        },
      },
    ],
    levelText: { read: "Read issues, boards and search", write: "Also create and edit issues and comments" },
  },
  {
    id: "confluence", name: "Confluence", mark: "C", color: "#1868db", env: "CONFLUENCE", blurb: "Spaces and pages",
    variants: [
      {
        id: "cloud", label: "Confluence Cloud", fields: [siteField(".atlassian.net", "your-team"), emailField("Atlassian account e-mail")],
        base: (v) => `https://${v.site}.atlassian.net/wiki`, auth: { type: "basic" }, username: (v) => v.email,
        headers: { "X-Atlassian-Token": "no-check" }, test: "/rest/api/user/current",
        token: () => ATLASSIAN_TOKENS, tokenHelp: () => "Create API token → name it “Hootway” → copy it. Jira and Confluence on the same site share this token.",
        levels: {
          read: [read("/rest/api/**", "/api/v2/**")],
          write: [read("/rest/api/**", "/api/v2/**"), rw(["POST", "PUT"], "/api/v2/pages/**", "/api/v2/footer-comments/**", "/rest/api/content/**")],
        },
      },
      {
        id: "dc", label: "Self-hosted (Data Center)", fields: [urlField("https://confluence.example.com")],
        base: (v) => v.url, auth: { type: "bearer" }, test: "/rest/api/user/current",
        headers: { "X-Atlassian-Token": "no-check" },
        token: (v) => `${v.url}/plugins/personalaccesstokens/usertokens.action`,
        tokenHelp: () => "Create token → name it “Hootway”, set an expiry → copy it. Needs Confluence 7.9 or newer.",
        levels: {
          read: [read("/rest/api/**")],
          write: [read("/rest/api/**"), rw(["POST", "PUT"], "/rest/api/content/**")],
        },
      },
    ],
    levelText: { read: "Read spaces, pages and comments", write: "Also create and edit pages and comments" },
  },
  {
    id: "bitbucket", name: "Bitbucket", mark: "B", color: "#2b62d9", env: "BITBUCKET", blurb: "Repositories and pull requests",
    variants: [
      {
        id: "cloud", label: "Bitbucket Cloud", fields: [emailField("Atlassian account e-mail")],
        base: () => "https://api.bitbucket.org", auth: { type: "basic" }, username: (v) => v.email, test: "/2.0/user",
        token: () => ATLASSIAN_TOKENS,
        tokenHelp: (l) => `Create API token with scopes → app Bitbucket → scopes read:user, read:repository, read:pullrequest${l === "write" ? ", write:pullrequest" : ""} → copy it.`,
        levels: {
          read: [read("/2.0/**")],
          write: [read("/2.0/**"), rw(["POST", "PUT"], "/2.0/repositories/*/*/pullrequests/**")],
        },
      },
      {
        id: "dc", label: "Self-hosted (Data Center)", fields: [urlField("https://bitbucket.example.com")],
        base: (v) => v.url, auth: { type: "bearer" }, test: "/rest/api/1.0/projects",
        token: (v) => `${v.url}/plugins/servlet/access-tokens/add`,
        tokenHelp: (l) => `Create token → name it “Hootway” → permissions Project read, Repository ${l === "write" ? "write" : "read"} → copy it.`,
        levels: {
          read: [read("/rest/api/**")],
          write: [read("/rest/api/**"), rw(["POST", "PUT"], "/rest/api/1.0/projects/*/repos/*/pull-requests/**")],
        },
      },
    ],
    levelText: { read: "Read repositories, code and pull requests", write: "Also open, comment on and update pull requests" },
  },
  {
    id: "gitlab", name: "GitLab", mark: "GL", color: "#e2432a", env: "GITLAB", blurb: "Projects, issues and merge requests",
    variants: [
      {
        id: "cloud", label: "GitLab.com", fields: [],
        base: () => "https://gitlab.com/api/v4", auth: { type: "bearer" }, test: "/user",
        token: (v, l) => `https://gitlab.com/-/user_settings/personal_access_tokens?name=Hootway&scopes=${l === "write" ? "api" : "read_api"}`,
        tokenHelp: (l) => `The form opens with name and scope (${l === "write" ? "api" : "read_api"}) filled in → set an expiry → Create token → copy it.`,
      },
      {
        id: "self", label: "Self-managed", fields: [urlField("https://gitlab.example.com")],
        base: (v) => `${v.url}/api/v4`, auth: { type: "bearer" }, test: "/user",
        token: (v, l) => `${v.url}/-/user_settings/personal_access_tokens?name=Hootway&scopes=${l === "write" ? "api" : "read_api"}`,
        tokenHelp: (l) => `The form opens with name and scope (${l === "write" ? "api" : "read_api"}) filled in → set an expiry → Create token → copy it.`,
      },
    ],
    levels: {
      read: [read("/**")],
      write: [read("/**"), rw(["POST", "PUT"], "/projects/*/issues/**", "/projects/*/merge_requests/**")],
    },
    levelText: { read: "Read projects, code, issues and merge requests", write: "Also create and update issues and merge requests" },
    note: "Address projects by numeric ID: Hootway rejects encoded slashes such as group%2Fproject.",
  },
  {
    id: "github", name: "GitHub", mark: "GH", color: "#24292f", env: "GITHUB", blurb: "Repositories, issues and pull requests",
    variants: [
      {
        id: "cloud", label: "GitHub.com", fields: [],
        base: () => "https://api.github.com", auth: { type: "bearer" }, test: "/user",
        token: (v, l) => "https://github.com/settings/personal-access-tokens/new?name=Hootway&description=Agent+access+through+Hootway&expires_in=90" +
          (l === "write" ? "&contents=read&issues=write&pull_requests=write" : "&contents=read&issues=read&pull_requests=read"),
        tokenHelp: () => "The fine-grained token form opens with name, expiry and permissions filled in → choose the resource owner and repositories → Generate token → copy it.",
      },
      {
        id: "ghes", label: "Enterprise Server", fields: [urlField("https://github.example.com")],
        base: (v) => `${v.url}/api/v3`, auth: { type: "bearer" }, test: "/user",
        token: (v) => `${v.url}/settings/tokens/new?description=Hootway&scopes=repo`,
        tokenHelp: () => "The classic token form opens with the repo scope selected → set an expiry → Generate token → copy it.",
      },
    ],
    headers: { "X-GitHub-Api-Version": "2022-11-28" },
    levels: {
      read: [read("/**")],
      write: [read("/**"), rw(["POST", "PATCH"], "/repos/*/*/issues/**", "/repos/*/*/pulls/**")],
    },
    levelText: { read: "Read repositories, issues and pull requests", write: "Also open and comment on issues and pull requests" },
  },
  {
    id: "gitea", name: "Gitea / Forgejo", mark: "Gi", color: "#609926", env: "GITEA", blurb: "Self-hosted Git, incl. HooGit and Codeberg",
    variants: [
      {
        id: "self", label: "Self-hosted", fields: [urlField("https://git.example.com")],
        base: (v) => `${v.url}/api/v1`, auth: { type: "bearer" }, test: "/user",
        token: (v) => `${v.url}/user/settings/applications`,
        tokenHelp: (l) => `Generate new token → name it “Hootway” → repository: ${l === "write" ? "Read and write" : "Read"}, issue: ${l === "write" ? "Read and write" : "Read"}, user: Read → copy it.`,
      },
    ],
    levels: {
      read: [read("/**")],
      write: [read("/**"), rw(["POST", "PATCH"], "/repos/*/*/issues/**", "/repos/*/*/pulls/**")],
    },
    levelText: { read: "Read repositories, issues and pull requests", write: "Also open and comment on issues and pull requests" },
  },
  {
    id: "linear", name: "Linear", mark: "L", color: "#5e6ad2", env: "LINEAR", blurb: "Issues and projects (GraphQL)",
    variants: [
      {
        id: "cloud", label: "Linear", fields: [],
        base: () => "https://api.linear.app", auth: { type: "header", name: "Authorization" }, test: null,
        token: () => "https://linear.app/settings/account/security",
        tokenHelp: (l) => `Personal API keys → New API key → name it “Hootway” → permission ${l === "write" ? "Read and write" : "Read"} → copy it.`,
      },
    ],
    levels: { read: [rw(["POST"], "/graphql")] },
    levelText: { read: "GraphQL endpoint; what the agent can do is set by the API key’s permission" },
    note: "Linear has a single GraphQL endpoint, so restrict access with the API key’s own permission (Read only is safest).",
  },
  {
    id: "plane", name: "Plane", mark: "P", color: "#3f76ff", env: "PLANE", blurb: "Work items, cycles and modules",
    variants: [
      {
        id: "cloud", label: "Plane Cloud", fields: [],
        base: () => "https://api.plane.so", auth: { type: "header", name: "X-API-Key" }, test: "/api/v1/users/me/",
        token: () => "https://app.plane.so/settings/profile/api-tokens",
        tokenHelp: () => "Add personal access token → name it “Hootway”, set an expiry → copy it.",
      },
      {
        id: "self", label: "Self-hosted", fields: [urlField("https://plane.example.com")],
        base: (v) => v.url, auth: { type: "header", name: "X-API-Key" }, test: "/api/v1/users/me/",
        token: (v) => `${v.url}/settings/profile/api-tokens`,
        tokenHelp: () => "Add personal access token → name it “Hootway”, set an expiry → copy it.",
      },
    ],
    levels: {
      read: [read("/api/v1/**")],
      write: [read("/api/v1/**"), rw(["POST", "PATCH"], "/api/v1/workspaces/*/projects/*/issues/**", "/api/v1/workspaces/*/projects/*/work-items/**")],
    },
    levelText: { read: "Read workspaces, projects and work items", write: "Also create, update and comment on work items" },
  },
  {
    id: "sentry", name: "Sentry", mark: "S", color: "#6c5fc7", env: "SENTRY", blurb: "Errors and issues",
    variants: [
      {
        id: "us", label: "sentry.io (US)", fields: [],
        base: () => "https://sentry.io/api/0", auth: { type: "bearer" }, test: "/organizations/",
        token: () => "https://sentry.io/settings/account/api/auth-tokens/new-token/",
      },
      {
        id: "eu", label: "sentry.io (EU)", fields: [],
        base: () => "https://de.sentry.io/api/0", auth: { type: "bearer" }, test: "/organizations/",
        token: () => "https://sentry.io/settings/account/api/auth-tokens/new-token/",
      },
      {
        id: "self", label: "Self-hosted", fields: [urlField("https://sentry.example.com")],
        base: (v) => `${v.url}/api/0`, auth: { type: "bearer" }, test: "/organizations/",
        token: (v) => `${v.url}/settings/account/api/auth-tokens/new-token/`,
      },
    ],
    tokenHelp: (l) => `Name it “Hootway” → scopes org:read, project:read, event:read${l === "write" ? ", event:write" : ""} → Create token → copy it.`,
    levels: {
      read: [read("/**")],
      write: [read("/**"), rw(["PUT"], "/organizations/*/issues/**", "/issues/**")],
    },
    levelText: { read: "Read organizations, projects, issues and events", write: "Also resolve, assign and update issues" },
  },
  {
    id: "grafana", name: "Grafana", mark: "Gr", color: "#f46800", env: "GRAFANA", blurb: "Dashboards, data sources and alerts",
    variants: [
      {
        id: "cloud", label: "Grafana Cloud", fields: [siteField(".grafana.net", "your-stack")],
        base: (v) => `https://${v.site}.grafana.net`, auth: { type: "bearer" }, test: "/api/folders",
        token: (v) => `https://${v.site}.grafana.net/org/serviceaccounts/create`,
      },
      {
        id: "self", label: "Self-hosted", fields: [urlField("https://grafana.example.com")],
        base: (v) => v.url, auth: { type: "bearer" }, test: "/api/folders",
        token: (v) => `${v.url}/org/serviceaccounts/create`,
      },
    ],
    tokenHelp: (l) => `Create a service account “hootway” with role ${l === "write" ? "Editor" : "Viewer"} → Add service account token → copy it.`,
    levels: {
      read: [read("/api/**"), rw(["POST"], "/api/ds/query")],
      write: [read("/api/**"), rw(["POST"], "/api/ds/query", "/api/dashboards/db", "/api/annotations")],
    },
    levelText: { read: "Read dashboards and run data source queries", write: "Also save dashboards and add annotations" },
  },
  {
    id: "notion", name: "Notion", mark: "N", color: "#37352f", env: "NOTION", blurb: "Pages and databases",
    variants: [
      {
        id: "cloud", label: "Notion", fields: [],
        base: () => "https://api.notion.com", auth: { type: "bearer" }, test: "/v1/users/me",
        headers: { "Notion-Version": "2022-06-28" },
        token: () => "https://www.notion.so/profile/integrations",
        tokenHelp: (l) => `New integration → type Internal, name “Hootway” → capabilities: Read content${l === "write" ? ", Update content, Insert content" : ""} → copy the secret. Then share the pages it may use with the integration.`,
      },
    ],
    levels: {
      read: [read("/v1/**"), rw(["POST"], "/v1/search", "/v1/databases/*/query")],
      write: [read("/v1/**"), rw(["POST"], "/v1/search", "/v1/databases/*/query", "/v1/pages", "/v1/comments"), rw(["PATCH"], "/v1/pages/*", "/v1/blocks/**")],
    },
    levelText: { read: "Search and read shared pages and databases", write: "Also create and edit pages, blocks and comments" },
  },
];
