import { Component } from "@angular/core";
import { CommonModule } from "@angular/common";
import { RouterOutlet } from "@angular/router";
import { FormsModule } from "@angular/forms";
import { invoke } from "@tauri-apps/api/core";

import { DashboardComponent } from "./components/dashboard/dashboard.component";
import { SettingsComponent } from "./components/settings/settings.component";
import { RoutingComponent } from "./components/routing/routing.component";
import { LogsComponent } from "./components/logs/logs.component";

import { ThemeService } from "./services/theme.service";

@Component({
  selector: "app-root",
  standalone: true,
  imports: [CommonModule, RouterOutlet, FormsModule],
  templateUrl: "./app.component.html",
  styleUrl: "./app.component.css",
})
export class AppComponent {
  greetingMessage = "";
  mainSwitchActive = false;
  selectedView: string = "dashboard";
  views: { [key: string]: any } = {
    dashboard: DashboardComponent,
    settings: SettingsComponent,
    routing: RoutingComponent,
    logs: LogsComponent,
  };

  currentView: any = this.views[this.selectedView];

  // greet(event: SubmitEvent, name: string): void {
  //   event.preventDefault();

  //   // Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
  //   invoke<string>("greet", { name }).then((text) => {
  //     this.greetingMessage = text;
  //   });
  // }

  onViewChange() {
    this.currentView = this.views[this.selectedView];
  }

  onMainSwitchChange() {
    if (this.mainSwitchActive) {
      console.log("Activating...");
    } else {
      console.log("Shutting Down...");
    }
  }

  constructor(private themeService: ThemeService) {}
  ngOnInit() {
    this.themeService.setTheme("dark");
  }
}
