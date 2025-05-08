import { Injectable } from "@angular/core";

@Injectable({
  providedIn: "root",
})
export class ThemeService {
  private readonly themeId = "app-theme";

  setTheme(themeName: string): void {
    const head = document.head;
    let themeLink = document.getElementById(this.themeId) as HTMLLinkElement;

    const href = `assets/color-schemes/${themeName}.css`;

    if (themeLink) {
      themeLink.href = href;
    } else {
      themeLink = document.createElement("link");
      themeLink.rel = "stylesheet";
      themeLink.id = this.themeId;
      themeLink.href = href;
      head.appendChild(themeLink);
    }
  }
  constructor() {}
}
