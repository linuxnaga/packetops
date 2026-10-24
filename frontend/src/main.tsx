import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { ApiError } from "./api/client";
import { AuthProvider } from "./lib/auth";
import { SelectionProvider } from "./lib/selection";
import { applyTheme, loadTheme } from "./lib/theme";
import "./index.css";

applyTheme(loadTheme());

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      refetchOnWindowFocus: false,
      // Client errors (403, 404, 422) will not change on retry.
      retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <SelectionProvider>
          <App />
        </SelectionProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);
