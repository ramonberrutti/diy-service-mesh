# DIY Service Mesh

This is a Do-It-Yourself Service Mesh, which is a learning platform for understanding 
the internals of a service mesh. The goal of this project is to provide a simple, 
easy-to-understand reference implementation of a service mesh, which can be used 
to learn about the various concepts and technologies used in a service mesh.

## What are you going to learn?

- How to build a simple proxy and add service mesh features to it.
- How to use Netfilter to intercept and modify network packets.
- How to create a simple control plane to manage the service mesh.
- How to use gRPC to communicate between the data plane and the control plane.
- How to create a Admision Controller to validate and mutate Kubernetes resources.

## Some considerations

- This is only for learning propose, not a production-ready service mesh.
- We are going to use IPTables instead of eBPF or Nftables for simplicity.
- We are going to keep the code as simple as possible to make it easy to understand.


## What are we going to build?

We are going to keep the project in a monorepo, which will contain the following components:

- **init-container**: This is an init container that we are going to use to configure the network namespace of the pods.
- **data-plane**: This is the data plane of the service mesh, which is responsible for intercepting and modifying network packets.
- **control-plane**: This is the control plane of the service mesh, which is responsible for managing the data plane.
- **admission-controller**: This is an Admission Controller for Kubernetes, which is responsible for validating and mutating Kubernetes resources.
- **sample-app**: This is a sample application that we are going to use to test the service mesh with different scenarios.

## How to run this project?

We are going to use:

- [kind](https://kind.sigs.k8s.io/) to create a Kubernetes cluster locally.
- [Tilt](https://tilt.dev/) to run the project and watch for changes.
- [Buf](https://buf.build/) to lint and generate the Protobuf/gRPC code.
- [Docker](https://www.docker.com/) to build the Docker images.
- [k9s](https://k9scli.io/) to interact with the Kubernetes cluster. (Optional)

To start all the components, run the following command:

```bash
tilt up
```

Will build all the images and deploy all the components to the Kubernetes cluster.


## Architecture

The architecture of the service mesh is composed of the following components:

![Architecture](./docs/images/architecture.png)



## Creating the applications

We are going to create three applications:

- **app-a**: This application if going to call the `app-b` service.
- **app-b**: This application is going to be called by the `app-a` service.
- **app-b2**: This application will be our canary deployment for the `app-b` service.

app-b1 and app-b2 are going to have the same code, but they are going to have different versions to simulate a canary deployment.
