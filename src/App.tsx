import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Switch } from './components/ui/switch';
import { Slider } from './components/ui/slider';
import { Badge } from './components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './components/ui/table';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from './components/ui/accordion';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer } from 'recharts';
import { Shield, Settings, AlertTriangle, CheckCircle, XCircle, TrendingUp, Scan, Globe } from 'lucide-react';

// Mock data for the chart
const threatData = [
  { day: 'Day 1', threats: 2 },
  { day: 'Day 5', threats: 1 },
  { day: 'Day 10', threats: 3 },
  { day: 'Day 15', threats: 1 },
  { day: 'Day 20', threats: 4 },
  { day: 'Day 25', threats: 2 },
  { day: 'Day 30', threats: 7 },
];

// Mock data for recent activity
const recentActivity = [
  { url: 'example.com/login', status: 'Safe', time: '2 min ago', riskLevel: 'safe' },
  { url: 'suspicious-bank.net', status: 'Dangerous', time: '5 min ago', riskLevel: 'dangerous' },
  { url: 'shopping-deals.com', status: 'Warning', time: '12 min ago', riskLevel: 'warning' },
  { url: 'news-website.org', status: 'Safe', time: '18 min ago', riskLevel: 'safe' },
  { url: 'fake-paypal.xyz', status: 'Dangerous', time: '25 min ago', riskLevel: 'dangerous' },
];

// Mock whitelist
const whitelistedSites = [
  'google.com',
  'github.com',
  'stackoverflow.com',
  'microsoft.com',
  'apple.com'
];

export default function App() {
  const [urlToCheck, setUrlToCheck] = useState('');
  const [urlResult, setUrlResult] = useState<{ status: string; score: number; risk: string } | null>(null);
  const [whoisDetails, setWhoisDetails] = useState<{
    domain_name: string;
    created_date: string;
    expires_date: string;
    registrar: string;
    registrant_org: string;
  } | null>(null);
  const [screenshotUrl, setScreenshotUrl] = useState<string | null>(null);
  const [screenshotLoading, setScreenshotLoading] = useState(false);
  const [realtimeScanning, setRealtimeScanning] = useState(true);
  const [sensitivity, setSensitivity] = useState([2]);
  const [newWhitelistUrl, setNewWhitelistUrl] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);

 const handleUrlCheck = async () => {
  if (!urlToCheck.trim()) return;

  setIsAnalyzing(true);

  try {
    const response = await fetch('http://localhost:5000/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: urlToCheck }),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    setUrlResult(data.model_result);
    setWhoisDetails(data.whois_details);
    setScreenshotUrl(data.screenshot_url);
  } catch (error) {
    console.error('Error analyzing URL:', error);

    // Fallback WHOIS and Screenshot if backend fails
    updateWhoisDisplay({
      domain_name: urlToCheck.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0],
      created_date: 'N/A',
      expires_date: 'N/A',
      registrar: 'N/A',
      registrant_org: 'Privacy Protected',
    });

    updateScreenshotDisplay(null);
  } finally {
    setIsAnalyzing(false);
  }
};


  const updateWhoisDisplay = (whoisData: {
    domain_name: string;
    created_date: string;
    expires_date: string;
    registrar: string;
    registrant_org: string;
  }) => {
    setWhoisDetails(whoisData);
  };

  const updateScreenshotDisplay = (screenshotUrl: string | null) => {
    setScreenshotUrl(screenshotUrl);
    if (screenshotUrl) {
      setScreenshotLoading(true);
    } else {
      setScreenshotLoading(false);
    }
  };

  const getSensitivityLabel = (value: number) => {
    if (value === 1) return 'Low';
    if (value === 2) return 'Medium';
    return 'High';
  };

  const getStatusBadge = (risk: string) => {
    const variants = {
      safe: 'bg-green-500/20 text-green-400 border-green-500/30',
      warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      dangerous: 'bg-red-500/20 text-red-400 border-red-500/30'
    };
    return variants[risk as keyof typeof variants] || variants.safe;
  };

  const getStatusIcon = (risk: string) => {
    if (risk === 'safe') return <CheckCircle className="w-4 h-4" />;
    if (risk === 'warning') return <AlertTriangle className="w-4 h-4" />;
    return <XCircle className="w-4 h-4" />;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 dark">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-xl text-white">PhishGuard Pro</h1>
              <p className="text-sm text-gray-400">Advanced Phishing Detection</p>
            </div>
          </div>
          <Button variant="ghost" size="icon" className="text-gray-400 hover:text-white">
            <Settings className="w-5 h-5" />
          </Button>
        </div>
      </header>

      <div className="flex h-[calc(100vh-88px)]">
        {/* Left Column - Settings & Manual Checks (30%) */}
        <div className="w-[30%] bg-gray-800 border-r border-gray-700 p-6 overflow-y-auto">
          <Accordion type="multiple" defaultValue={["manual-check", "controls", "whitelist"]} className="space-y-4">

            {/* Manual URL Checker */}
            <AccordionItem value="manual-check" className="border-gray-700">
              <AccordionTrigger className="text-white hover:text-cyan-400">
                <div className="flex items-center gap-2">
                  <Scan className="w-4 h-4" />
                  Manual URL Checker
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 pt-4">
                <div>
                  <Label htmlFor="url-input" className="text-gray-300">Check a Suspicious URL</Label>
                  <Input
                    id="url-input"
                    placeholder="Enter URL to analyze..."
                    value={urlToCheck}
                    onChange={(e) => setUrlToCheck(e.target.value)}
                    className="mt-2 bg-gray-700 border-gray-600 text-white placeholder:text-gray-400"
                  />
                </div>

                <Button
                  onClick={handleUrlCheck}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 text-white"
                  disabled={!urlToCheck.trim() || isAnalyzing}
                >
                  {isAnalyzing ? 'Analyzing...' : 'Analyze URL'}
                </Button>

                {/* Result Card */}
                <Card className="bg-gray-700 border-gray-600">
                  <CardContent className="p-4">
                    {urlResult ? (
                      <div className="text-center space-y-2">
                        <div className="flex items-center justify-center gap-2">
                          {getStatusIcon(urlResult.risk)}
                          <Badge className={getStatusBadge(urlResult.risk)}>
                            {urlResult.status}
                          </Badge>
                        </div>
                        <div className="text-2xl text-white">
                          Risk Score: {urlResult.score}/100
                        </div>
                      </div>
                    ) : (
                      <p className="text-center text-gray-400">Enter a URL to check</p>
                    )}
                  </CardContent>
                </Card>
              </AccordionContent>
            </AccordionItem>

            {/* Core Controls */}
            <AccordionItem value="controls" className="border-gray-700">
              <AccordionTrigger className="text-white hover:text-cyan-400">
                <div className="flex items-center gap-2">
                  <Settings className="w-4 h-4" />
                  Core Controls
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-6 pt-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="realtime-toggle" className="text-gray-300">Enable Auto-Scanning</Label>
                  <Switch
                    id="realtime-toggle"
                    checked={realtimeScanning}
                    onCheckedChange={setRealtimeScanning}
                  />
                </div>

                <div className="space-y-3">
                  <Label className="text-gray-300">Detection Sensitivity</Label>
                  <div className="px-2">
                    <Slider
                      value={sensitivity}
                      onValueChange={setSensitivity}
                      max={3}
                      min={1}
                      step={1}
                      className="w-full"
                    />
                    <div className="flex justify-between text-xs text-gray-500 mt-1">
                      <span>Low</span>
                      <span>Medium</span>
                      <span>High</span>
                    </div>
                  </div>
                  <p className="text-sm text-cyan-400">
                    Current: {getSensitivityLabel(sensitivity[0])}
                  </p>
                </div>
              </AccordionContent>
            </AccordionItem>

            {/* Whitelist Management */}
            <AccordionItem value="whitelist" className="border-gray-700">
              <AccordionTrigger className="text-white hover:text-cyan-400">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  Trusted Sites
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 pt-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="Add trusted domain..."
                    value={newWhitelistUrl}
                    onChange={(e) => setNewWhitelistUrl(e.target.value)}
                    className="bg-gray-700 border-gray-600 text-white placeholder:text-gray-400"
                  />
                  <Button size="sm" variant="outline" className="border-gray-600 text-gray-300 hover:bg-gray-700">
                    Add
                  </Button>
                </div>

                <div className="space-y-2 max-h-32 overflow-y-auto">
                  {whitelistedSites.map((site, index) => (
                    <div key={index} className="text-sm text-gray-300 p-2 bg-gray-700 rounded border border-gray-600">
                      {site}
                    </div>
                  ))}
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </div>

        {/* Right Column - Metrics & History (70%) */}
        <div className="flex-1 p-6 space-y-6 overflow-y-auto">

          {/* WHOIS Domain Intelligence Section */}
          <div className="whois-card-top-detail bg-gray-800 border border-gray-700 rounded-lg p-6">
            <h3 className="text-lg font-semibold text-white mb-4">
              Domain Intelligence: <span className="text-cyan-400">{whoisDetails?.domain_name || 'N/A'}</span>
            </h3>
            <ul className="info-list space-y-2">
              <li className="flex justify-between items-center">
                <strong className="text-gray-300">Creation Date:</strong>
                <span className="text-gray-100">{whoisDetails?.created_date || 'Loading...'}</span>
              </li>
              <li className="flex justify-between items-center">
                <strong className="text-gray-300">Expiration Date:</strong>
                <span className="text-gray-100">{whoisDetails?.expires_date || 'Loading...'}</span>
              </li>
              <li className="flex justify-between items-center">
                <strong className="text-gray-300">Registrar:</strong>
                <span className="text-gray-100">{whoisDetails?.registrar || 'Loading...'}</span>
              </li>
              <li className="flex justify-between items-center">
                <strong className="text-gray-300">Registrant Org:</strong>
                <span className="text-gray-100">{whoisDetails?.registrant_org || 'N/A'}</span>
              </li>
            </ul>
          </div>

          {/* Screenshot Preview Card */}
          <div className="screenshot-preview-card bg-gray-800 border border-gray-700 rounded-lg p-6" style={{ marginBottom: '20px' }}>
            <h3 className="text-lg font-semibold text-white mb-4">Safe Visual Preview</h3>
            <div style={{ maxHeight: '400px', overflow: 'hidden', borderRadius: '8px', backgroundColor: '#374151' }}>
              {screenshotUrl && (
                <img
                  id="site-preview-image"
                  src={screenshotUrl}
                  alt="Website Preview"
                  style={{ maxWidth: '100%', height: 'auto', display: screenshotLoading ? 'none' : 'block' }}
                  onLoad={() => setScreenshotLoading(false)}
                  onError={() => {
                    setScreenshotLoading(false);
                    console.error('Failed to load screenshot');
                  }}
                />
              )}
              {screenshotLoading && (
                <div className="flex items-center justify-center h-64">
                  <p id="preview-loading-text" className="text-gray-400">Generating screenshot...</p>
                </div>
              )}
              {!screenshotUrl && !screenshotLoading && (
                <div className="flex items-center justify-center h-64">
                  <p className="text-gray-400">Screenshot will appear here after analysis</p>
                </div>
              )}
            </div>
          </div>

          {/* Security Snapshot Cards */}
          <div className="grid grid-cols-3 gap-6">
            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-gray-300">
                  <Scan className="w-5 h-5 text-green-400" />
                  Total Scans
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl text-white">548</div>
                <p className="text-sm text-gray-400">Sites analyzed</p>
              </CardContent>
            </Card>

            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-gray-300">
                  <XCircle className="w-5 h-5 text-red-400" />
                  Threats Detected
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl text-white">7</div>
                <p className="text-sm text-gray-400">Dangerous sites</p>
              </CardContent>
            </Card>

            <Card className="bg-gray-800 border-gray-700">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-gray-300">
                  <TrendingUp className="w-5 h-5 text-cyan-400" />
                  Click-Through Rate
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl text-white">0.5%</div>
                <p className="text-sm text-gray-400">User clicks on threats</p>
              </CardContent>
            </Card>
          </div>

          {/* Threat Trend Chart */}
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-white">Threats Detected Over Last 30 Days</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={threatData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis
                      dataKey="day"
                      stroke="#9CA3AF"
                      fontSize={12}
                    />
                    <YAxis
                      stroke="#9CA3AF"
                      fontSize={12}
                    />
                    <Line
                      type="monotone"
                      dataKey="threats"
                      stroke="#06B6D4"
                      strokeWidth={2}
                      dot={{ fill: '#06B6D4', strokeWidth: 2, r: 4 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Recent Activity Table */}
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-white">Recent Analysis History</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-gray-700">
                    <TableHead className="text-gray-300">URL</TableHead>
                    <TableHead className="text-gray-300">Risk Status</TableHead>
                    <TableHead className="text-gray-300">Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentActivity.map((activity, index) => (
                    <TableRow key={index} className="border-gray-700">
                      <TableCell className="text-gray-300 font-mono text-sm">
                        {activity.url}
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusBadge(activity.riskLevel)}>
                          {activity.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-gray-400 text-sm">
                        {activity.time}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="mt-4">
                <Button variant="link" className="text-cyan-400 hover:text-cyan-300 p-0">
                  View Full History →
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
