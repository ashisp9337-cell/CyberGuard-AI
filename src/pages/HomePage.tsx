import { HomeNavbar } from "@/components/home/HomeNavbar";
import { HeroSection } from "@/components/home/HeroSection";
import { TrustBar } from "@/components/home/TrustBar";
import { ProblemSection } from "@/components/home/ProblemSection";
import { SolutionSection } from "@/components/home/SolutionSection";
import { ModuleGrid } from "@/components/home/ModuleGrid";
import { CapabilitiesSection } from "@/components/home/CapabilitiesSection";
import { HowItWorks } from "@/components/home/HowItWorks";
import { DashboardPreview } from "@/components/home/DashboardPreview";
import { WhyCyberGuard } from "@/components/home/WhyCyberGuard";
import { StatsSection } from "@/components/home/StatsSection";
import { TechnologySection } from "@/components/home/TechnologySection";
import { VisionSection } from "@/components/home/VisionSection";
import { MissionSection } from "@/components/home/MissionSection";
import { FinalCTA } from "@/components/home/FinalCTA";
import { HomeFooter } from "@/components/home/HomeFooter";

export default function HomePage() {
  return (
    <div className="bg-canvas min-h-screen">
      <HomeNavbar />
      <main>
        <HeroSection />
        <TrustBar />
        <ProblemSection />
        <SolutionSection />
        <ModuleGrid />
        <CapabilitiesSection />
        <HowItWorks />
        <DashboardPreview />
        <WhyCyberGuard />
        <StatsSection />
        <TechnologySection />
        <VisionSection />
        <MissionSection />
        <FinalCTA />
      </main>
      <HomeFooter />
    </div>
  );
}
