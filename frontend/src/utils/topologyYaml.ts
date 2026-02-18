import yaml from 'js-yaml';
import type { NetworkTopology, NodeGroup } from '../types/api';

/**
 * Export topology to YAML string
 */
export function exportTopologyToYaml(topology: NetworkTopology): string {
  // Create a clean topology object without status for export
  const exportData: NetworkTopology = {
    apiVersion: topology.apiVersion || 'simulation.kuro.io/v1alpha1',
    kind: topology.kind || 'NetworkTopology',
    metadata: {
      name: topology.metadata.name,
      namespace: topology.metadata.namespace || 'default',
      creationTimestamp: topology.metadata.creationTimestamp,
      labels: topology.metadata.labels,
      annotations: topology.metadata.annotations,
      uid: '',  // Don't export uid
    },
    spec: {
      nodeGroups: topology.spec.nodeGroups.map((group: NodeGroup) => ({
        name: group.name,
        replicas: group.replicas,
        image: group.image,
        labels: group.labels,
        resources: group.resources,
      })),
    },
  };

  return yaml.dump(exportData, {
    indent: 2,
    lineWidth: -1,
    noRefs: true,
    sortKeys: false,
  });
}

/**
 * Download topology as YAML file
 */
export function downloadTopologyYaml(topology: NetworkTopology): void {
  const yamlContent = exportTopologyToYaml(topology);
  const blob = new Blob([yamlContent], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  
  const link = document.createElement('a');
  link.href = url;
  link.download = `${topology.metadata.name}.yaml`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Parse imported YAML file
 */
export function parseImportedYaml(content: string): { 
  topology: NetworkTopology | null; 
  error: string | null;
} {
  try {
    const parsed = yaml.load(content) as unknown;

    if (!parsed || typeof parsed !== 'object') {
      return { topology: null, error: 'Invalid YAML structure' };
    }

    const topology = parsed as NetworkTopology;

    // Validate kind
    if (topology.kind !== 'NetworkTopology') {
      return { topology: null, error: 'Kind must be NetworkTopology' };
    }

    // Validate apiVersion
    if (!topology.apiVersion) {
      return { topology: null, error: 'apiVersion is required' };
    }

    // Validate metadata.name
    if (!topology.metadata?.name) {
      return { topology: null, error: 'metadata.name is required' };
    }

    // Validate spec.nodeGroups
    if (!topology.spec?.nodeGroups || !Array.isArray(topology.spec.nodeGroups)) {
      return { topology: null, error: 'spec.nodeGroups array is required' };
    }

    if (topology.spec.nodeGroups.length === 0) {
      return { topology: null, error: 'At least one nodeGroup is required' };
    }

    // Validate each nodeGroup
    for (const group of topology.spec.nodeGroups) {
      if (!group.name) {
        return { topology: null, error: 'Each nodeGroup must have a name' };
      }
      if (!group.image) {
        return { topology: null, error: `NodeGroup "${group.name}" must have an image` };
      }
      if (group.replicas === undefined || group.replicas < 0) {
        return { topology: null, error: `NodeGroup "${group.name}" must have a valid replicas count` };
      }
    }

    // Set defaults
    const validatedTopology: NetworkTopology = {
      apiVersion: topology.apiVersion,
      kind: topology.kind,
      metadata: {
        name: topology.metadata.name,
        namespace: topology.metadata.namespace || 'default',
        uid: '',
        creationTimestamp: new Date().toISOString(),
        labels: topology.metadata.labels,
        annotations: topology.metadata.annotations,
      },
      spec: {
        nodeGroups: topology.spec.nodeGroups.map((group: NodeGroup) => ({
          name: group.name,
          replicas: group.replicas || 1,
          image: group.image,
          labels: group.labels || {},
          resources: group.resources,
        })),
      },
    };

    return { topology: validatedTopology, error: null };
  } catch (e) {
    const errorMessage = e instanceof Error ? e.message : 'Unknown parsing error';
    return { topology: null, error: errorMessage };
  }
}

/**
 * Read file as text
 */
export function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}
