import { Component } from "@angular/core";
import { CommonModule } from "@angular/common";
import { ThemeService } from "../../services/theme.service";

@Component({
  selector: "app-dashboard",
  standalone: true,
  templateUrl: "./dashboard.component.html",
  imports: [CommonModule],
  styleUrls: ["./dashboard.component.css"],
})
export class DashboardComponent {
  connected = false;
  uptime = 0;
  intervalId: any;

  toggleConnection(): void {
    this.connected = !this.connected;
    if (this.connected) {
      this.intervalId = setInterval(() => this.uptime++, 1000);
    } else {
      clearInterval(this.intervalId);
      this.uptime = 0;
    }
  }

  formatTime(seconds: number): string {
    const h = Math.floor(seconds / 3600)
      .toString()
      .padStart(2, "0");
    const m = Math.floor((seconds % 3600) / 60)
      .toString()
      .padStart(2, "0");
    const s = (seconds % 60).toString().padStart(2, "0");
    return `${h}:${m}:${s}`;
  }

  constructor(private themeService: ThemeService) {}
  ngOnInit() {
    this.themeService.setTheme("dark");
  }
}
