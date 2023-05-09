<?php

/**
 * @package    Grav\Plugin\Login
 *
 * @copyright  Copyright (C) 2014 - 2021 RocketTheme, LLC. All rights reserved.
 * @license    MIT License; see LICENSE file for details.
 */

namespace Grav\Plugin\Login\TwoFactorAuth;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer as BaconImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle as BaconRendererStyle;
use BaconQrCode\Writer as BaconWriter;
use RobThree\Auth\Providers\Qr\IQRCodeProvider;

class BaconQrProvider implements IQRCodeProvider
{
    public function getMimeType()
    {
        return 'image/svg+xml';
    }

    public function getQRCodeImage($qrtext, $size = 256)
    {
        $renderer = new BaconImageRenderer(
            new BaconRendererStyle((int) $size),
            new SvgImageBackEnd()
        );

        $writer = new BaconWriter($renderer);

        return $writer->writeString($qrtext);
    }
}
