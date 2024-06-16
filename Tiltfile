version_settings(constraint='>=0.22.2')

load('ext://configmap', 'configmap_create')

# Generate the controller image.
docker_build(
    'diy-sm-controller',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/controller/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'controller',
    },
)

# Generate the proxy image.
docker_build(
    'diy-sm-proxy',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/proxy/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'proxy',
    },
    match_in_env_vars=True, # To inject into the injector env vars
)

# Generate the proxy-init image.
docker_build(
    'diy-sm-proxy-init',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/proxy-init/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'proxy-init',
        'SET_CAP': 'true',
    },
    match_in_env_vars=True, # To inject into the injector env vars
)

# Generate the proxy injector image.
docker_build(
    'diy-sm-injector',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/injector/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'injector',
    },
)

# Generate the http-client image.
docker_build(
    'diy-sm-http-client',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/http-client/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'http-client',
    },
)

# Generate the http-server image.
docker_build(
    'diy-sm-http-server',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/http-server/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'http-server',
    },
)

# Generate the grpc-client image.
docker_build(
    'diy-sm-grpc-client',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/grpc-client/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'grpc-client',
    },
)

# Generate the grpc-client image.
docker_build(
    'diy-sm-grpc-server',
    context='.',
    dockerfile='./Dockerfile',
    only=[
        './go.mod', 
        './go.sum', 
        './cmd/grpc-server/',
        './protogen/',
        './vendor/',
    ],
    build_args={
        'APP_NAME': 'grpc-server',
    },
)

# Generate the proto files
local_resource(
    'protobuild',
    cmd='PATH="$PATH:$(pwd)/bin" buf generate',
    deps=[
        'proto',
        'buf.gen.yaml'
    ],
)

# Apply resources to the cluster
k8s_yaml('k8s/controller.yaml')
k8s_yaml('k8s/injector.yaml', allow_duplicates=True)
k8s_yaml('k8s/http-client.yaml')
k8s_yaml('k8s/http-server.yaml')
k8s_yaml('k8s/grpc-client.yaml')
k8s_yaml('k8s/grpc-server.yaml')
