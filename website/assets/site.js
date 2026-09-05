const header = document.querySelector("[data-header]");
const menuButton = document.querySelector("[data-menu-button]");
const mobileNav = document.querySelector("[data-mobile-nav]");
const isChinese = document.documentElement.lang.startsWith("zh");
const uiCopy = isChinese
  ? { openMenu: "打开菜单", closeMenu: "关闭菜单", copied: "已复制", copyFailed: "复制失败" }
  : { openMenu: "Open menu", closeMenu: "Close menu", copied: "Copied", copyFailed: "Copy failed" };

// Real locale links work without JavaScript; retain the current section when available.
const updateLanguageLinks = () => {
  document.querySelectorAll("[data-language-switch]").forEach((link) => {
    const url = new URL(link.href);
    url.hash = window.location.hash;
    link.href = url.href;
  });
};
updateLanguageLinks();
window.addEventListener("hashchange", updateLanguageLinks);

const updateHeader = () => {
  header?.classList.toggle("scrolled", window.scrollY > 20);
};

updateHeader();
window.addEventListener("scroll", updateHeader, { passive: true });

menuButton?.addEventListener("click", () => {
  const isOpen = menuButton.getAttribute("aria-expanded") === "true";
  menuButton.setAttribute("aria-expanded", String(!isOpen));
  menuButton.setAttribute("aria-label", isOpen ? uiCopy.openMenu : uiCopy.closeMenu);
  mobileNav?.classList.toggle("open", !isOpen);
  document.body.classList.toggle("menu-open", !isOpen);
});

mobileNav?.querySelectorAll("a").forEach((link) => {
  link.addEventListener("click", () => {
    menuButton?.setAttribute("aria-expanded", "false");
    menuButton?.setAttribute("aria-label", uiCopy.openMenu);
    mobileNav?.classList.remove("open");
    document.body.classList.remove("menu-open");
  });
});

const revealElements = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: "0px 0px -30px" },
  );
  revealElements.forEach((element) => observer.observe(element));
} else {
  revealElements.forEach((element) => element.classList.add("visible"));
}

const profileCopy = {
  conversation: {
    title: "llm-conversation-text-v1",
    description: isChinese ? "覆盖请求与响应的纯文本消息" : "Covers plain-text request and response messages",
  },
  stream: {
    title: "llm-request-upstream-v1",
    description: isChinese
      ? "覆盖流式请求与上游响应 metadata；不覆盖流正文"
      : "Covers the streaming request and upstream response metadata; excludes the stream body",
  },
};

const profileNote = document.querySelector("[data-profile-note]");
document.querySelectorAll("[data-profile]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-profile]").forEach((candidate) => {
      const active = candidate === button;
      candidate.classList.toggle("active", active);
      candidate.setAttribute("aria-selected", String(active));
    });
    const copy = profileCopy[button.dataset.profile];
    if (profileNote && copy) {
      profileNote.querySelector("strong").textContent = copy.title;
      profileNote.querySelector("span").textContent = copy.description;
    }
  });
});

document.querySelectorAll(".copy-button").forEach((button) => {
  button.addEventListener("click", async () => {
    const code = button.closest(".code-block")?.querySelector("code")?.textContent;
    if (!code) return;
    const original = button.textContent;
    button.disabled = true;
    try {
      await navigator.clipboard.writeText(code);
      button.textContent = uiCopy.copied;
    } catch {
      button.textContent = uiCopy.copyFailed;
    } finally {
      window.setTimeout(() => {
        button.textContent = original;
        button.disabled = false;
      }, 1500);
    }
  });
});

const docSections = [...document.querySelectorAll(".docs-content > section[id]")];
const docLinks = [...document.querySelectorAll(".docs-sidebar nav a")];
if (docSections.length && docLinks.length && "IntersectionObserver" in window) {
  const docObserver = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (!visible) return;
      docLinks.forEach((link) => {
        link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`);
      });
    },
    { rootMargin: "-18% 0px -70%" },
  );
  docSections.forEach((section) => docObserver.observe(section));
}
