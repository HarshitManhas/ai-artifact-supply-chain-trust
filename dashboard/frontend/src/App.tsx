import React from 'react';
import { CssBaseline, Container, Typography, Box, Button } from '@mui/material';

function App() {
  const [health, setHealth] = React.useState<string>('unknown');

  const checkHealth = async () => {
    try {
      const res = await fetch('/health');
      const json = await res.json();
      setHealth(json.status || 'unknown');
    } catch (e) {
      setHealth('unreachable');
    }
  };

  React.useEffect(() => {
    checkHealth();
  }, []);

  return (
    <>
      <CssBaseline />
      <Container maxWidth="md">
        <Box sx={{ my: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            AI Artifact Supply Chain Trust Dashboard
          </Typography>
          <Typography variant="body1" gutterBottom>
            Backend health: {health}
          </Typography>
          <Button variant="contained" onClick={checkHealth}>Refresh</Button>
        </Box>
      </Container>
    </>
  );
}

export default App;
